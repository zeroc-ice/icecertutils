#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

import os, random, tempfile, glob

from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, d

def toDNSection(dn):
    s = "[ dn ]\n"
    for k, v in [ ("countryName", "C"),
                  ("organizationalUnitName", "OU"),
                  ("organizationName", "O"),
                  ("localityName", "L"),
                  ("stateOrProvinceName", "ST"),
                  ("commonName", "CN"),
                  ("emailAddress", "emailAddress")]:
        if hasattr(dn, v):
            value = getattr(dn, v)
            if value:
                s += "{k} = {v}\n".format(k = k, v = value)
    return s

class OpenSSLCertificate(Certificate):
    def __init__(self, *args):
        Certificate.__init__(self, *args)
        self.pem = os.path.join(self.parent.home, self.alias + ".pem")
        self.key = os.path.join(self.parent.home, self.alias + "_key.pem")

    def exists(self):
        return os.path.exists(self.pem) and os.path.exists(self.key)

    def load(self):
        subject = d(self.openSSL("x509", "-noout", "-subject"))
        if subject:
            self.dn = DistinguishedName.parse(subject[subject.find("=") + 1:].replace("/", ","))
        return self

    def toText(self):
        return d(self.openSSL("x509", "-noout", "-text"))

    def savePKCS12(self, path, password="password", chain=True):
        if self == self.parent.cacert:
            # If saving CA cert, just save the certificate without the key
            self.openSSL("pkcs12", "-nokeys", out=path, password=password)
        elif chain:
            # Save the certificate chain to PKCS12
            self.openSSL("pkcs12", "-chain", out=path, inkey=self.key, CAfile=self.parent.cacert.pem, password=password)
        else:
            # Save the certificate to PKCS12
            self.openSSL("pkcs12", out=path, inkey=self.key, password=password)
        return self

    def savePEM(self, path):
        self.openSSL("x509", outform="PEM", out=path)
        return self

    def saveDER(self, path):
        self.openSSL("x509", outform="DER", out=path)
        return self

    def destroy(self):
        if os.path.exists(self.key):
            os.remove(self.key)
        Certificate.destroy(self)

    def openSSL(self, *args, **kargs):
        return self.parent.openSSL(cert=self, *args, **kargs)

class OpenSSLCertificateFactory(CertificateFactory):
    def __init__(self, *args, **kargs):
        CertificateFactory.__init__(self, *args, **kargs)

        self.cacert = self.get("ca")
        if not self.cacert:
            self.cacert = OpenSSLCertificate(self, "ca", self.dn)
            self.certs["ca"] = self.cacert
            self.cacert.openSSL("req", "-x509", config =
                                """
                                [ req ]
                                x509_extensions = ext
                                distinguished_name = dn
                                prompt = no
                                [ ext ]
                                basicConstraints = CA:true
                                subjectKeyIdentifier = hash
                                authorityKeyIdentifier = keyid:always,issuer:always
                                {dn}
                                """.format(dn=toDNSection(self.cacert.dn)))
        self.dn = self.cacert.dn

    def _createChild(self, *args):
        return OpenSSLCertificate(self, *args)

    def _generateChild(self, alias, dn=None, ip=None, dns=None):

        subAltName = ""
        if ip and dns:
            subAltName = "subjectAltName = DNS: {dns}, IP: {ip}"
        elif ip:
            subAltName = "subjectAltName = IP: {ip}"
        elif dns:
            subAltName = "subjectAltName = DNS: {dns}"

        cert = OpenSSLCertificate(self, alias, dn or ip or alias)

        # Generate a certificate request
        req = cert.openSSL("req", config=
                           """
                           [ req ]
                           distinguished_name = dn
                           prompt = no
                           {dn}
                           """.format(dn=toDNSection(cert.dn)))

        # Sign the certificate
        cert.openSSL("x509", "-req", set_serial=random.getrandbits(64), stdin=req, extfile=
                     """
                     [ ext ]
                     subjectKeyIdentifier = hash
                     authorityKeyIdentifier = keyid:always,issuer:always
                     keyUsage = nonRepudiation, digitalSignature, keyEncipherment
                     {subAltName}
                     """.format(subAltName = subAltName.format(dns=dns,ip=ip)))

        return cert

    def list(self):
        return [os.path.basename(a).replace("_key.pem","") for a in glob.glob(os.path.join(self.home, "*_key.pem"))]

    def openSSL(self, cmd, *args, **kargs):
        command = "openssl {cmd}".format(cmd = cmd)

        # Consume cert argument
        cert = kargs.get("cert", None)
        if cert: del kargs["cert"]

        # Consume config/extfile arguments
        tmpfiles = []
        for a in ["config", "extfile"]:
            data = kargs.get(a, None)
            if data:
                del kargs[a]
                (f, path) = tempfile.mkstemp()
                os.write(f, b(data))
                os.close(f)
                command += " -{a} {path}".format(a=a, path=path)
                tmpfiles.append(path)

        # Consume password argument
        password = kargs.get("password", None)
        if password: del kargs["password"]

        #
        # Write password to safe temporary file
        #
        passpath = None
        if password:
            (f, passpath) = tempfile.mkstemp()
            os.write(f, b(password))
            os.close(f)
            tmpfiles.append(passpath)

        #
        # Key creation and certificate request parameters
        #
        if cmd == "req":
            command += " -keyform PEM -keyout {cert.key} -newkey {this.keyalg}:{this.keysize}"
            if "-x509" in args:
                command += " -out {cert.pem} -passout file:{this.passpath}" # CA self-signed certificate
            else:
                command += " -passout file:{this.passpath}"

        #
        # Signature parameters for "req -x509" (CA self-signed certificate) or
        # "x509 -req" (signing certificate request)
        #
        if (cmd == "req" and "-x509" in args) or (cmd == "x509" and "-req" in args):
            command += " -{this.sigalg} -days {this.validity}"

        #
        # Certificate request signature parameters
        #
        if cmd == "x509" and "-req" in args:
            command += " -CA {cacert.pem} -CAkey {cacert.key} -passin file:{this.passpath} -extensions ext " \
                       "-out {cert.pem}"

        #
        # Export certificate parameters
        #
        if cmd == "x509" and not "-req" in args:
            command += " -in {cert.pem}"
        elif cmd == "pkcs12":
            command += " -in {cert.pem} -name {cert.alias} -export -passin file:{this.passpath} -passout file:{passpath}"

        command = command.format(cert = cert, cacert = self.cacert, this = self, passpath=passpath)
        try:
            return self.run(command, *args, **kargs)
        finally:
            for f in tmpfiles: # Remove temporary configuration files
                os.remove(f)
