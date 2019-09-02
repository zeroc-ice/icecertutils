#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

import os, random, tempfile, glob

from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, d, read, write

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

    def getSubjectHash(self):
        return d(self.openSSL("x509", "-noout", "-subject_hash"))

    def saveKey(self, path, password=None):
        (_, ext) = os.path.splitext(path)
        outform = "PEM"
        if ext == ".der" or ext == ".crt" or ext == ".cer":
            outform = "DER"
        #self.openSSL(self.parent.keyalg, outform=outform, out=path, password=password)
        self.openSSL("pkcs8", "-nocrypt -topk8", outform=outform, out=path, password=password)
        return self

    def savePKCS12(self, path, password=None, chain=True, root=False, addkey=None):
        if addkey is None:
            addkey = self != self.parent.cacert

        chainfile = None
        if chain:
            # Save the certificate chain to PKCS12
            certs = ""
            parent = self.parent
            while parent if root else parent.parent:
                certs += d(read(parent.cacert.pem))
                parent = parent.parent
            if len(certs) > 0:
                (f, chainfile) = tempfile.mkstemp()
                os.write(f, b(certs))
                os.close(f)

        key = "-inkey={0}".format(self.key) if addkey else "-nokeys"
        try:
            self.openSSL("pkcs12", out=path, inkey=self.key, certfile=chainfile, password=password or "password")
        finally:
            if chainfile:
                os.remove(chainfile)
        return self

    def savePEM(self, path, chain=True, root=False):
        text = self.openSSL("x509", outform="PEM")
        if chain:
            parent = self.parent
            while parent if root else parent.parent:
                text += parent.cacert.openSSL("x509", outform="PEM")
                parent = parent.parent
        write(path, text)
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

        if self.keyalg == "dsa":
            self.keyparams = os.path.join(self.home, "dsaparams.pem")
            if not os.path.exists(self.keyparams):
                self.run("openssl dsaparam  -outform PEM -out {0} {1}".format(self.keyparams, self.keysize))
        else:
            self.keyparams = self.keysize

        if not self.cacert.exists():

            subAltName = self.cacert.getAlternativeName()
            issuerAltName = self.parent.cacert.getAlternativeName() if self.parent else None
            altName = (("\nsubjectAltName = " + subAltName) if subAltName else "") + \
                      (("\nissuerAltName = " + issuerAltName) if issuerAltName else "")

            cacert = self.cacert
            if not self.parent:
                cacert.openSSL("req", "-x509", days = self.validity, config =
                               """
                               [ req ]
                               x509_extensions = ext
                               distinguished_name = dn
                               prompt = no
                               [ ext ]
                               basicConstraints = CA:true
                               subjectKeyIdentifier = hash
                               authorityKeyIdentifier = keyid:always,issuer:always
                               {altName}
                               {dn}
                               """.format(dn=toDNSection(cacert.dn),altName=altName))
            else:
                self.cacert = self.parent.cacert
                req = cacert.openSSL("req", config=
                                     """
                                     [ req ]
                                     distinguished_name = dn
                                     prompt = no
                                     {dn}
                                     """.format(dn=toDNSection(cacert.dn)))

                # Sign the certificate
                cacert.openSSL("x509", "-req", set_serial=random.getrandbits(64), stdin=req, days = self.validity,
                               extfile=
                               """
                               [ ext ]
                               basicConstraints = CA:true
                               subjectKeyIdentifier = hash
                               authorityKeyIdentifier = keyid:always,issuer:always
                               {altName}
                               """.format(altName=altName))

            self.cacert = cacert

    def _createFactory(self, *args, **kargs):
        return OpenSSLCertificateFactory(*args, **kargs)

    def _createChild(self, *args):
        return OpenSSLCertificate(self, *args)

    def _generateChild(self, cert, serial, validity):
        subAltName = cert.getAlternativeName()
        issuerAltName = self.cacert.getAlternativeName()
        altName = (("\nsubjectAltName = " + subAltName) if subAltName else "") + \
                  (("\nissuerAltName = " + issuerAltName) if issuerAltName else "")

        extendedKeyUsage = cert.getExtendedKeyUsage()
        extendedKeyUsage = ("extendedKeyUsage = " + extendedKeyUsage) if extendedKeyUsage else ""

        # Generate a certificate request
        req = cert.openSSL("req", config=
                           """
                           [ req ]
                           distinguished_name = dn
                           prompt = no
                           {dn}
                           """.format(dn=toDNSection(cert.dn)))

        # Sign the certificate
        cert.openSSL("x509", "-req", set_serial=serial or random.getrandbits(64), stdin=req,
                     days = validity or self.validity, extfile=
                     """
                     [ ext ]
                     subjectKeyIdentifier = hash
                     authorityKeyIdentifier = keyid:always,issuer:always
                     keyUsage = nonRepudiation, digitalSignature, keyEncipherment
                     {extendedKeyUsage}
                     {altName}
                     """.format(altName=altName, extendedKeyUsage=extendedKeyUsage))

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
            command += " -keyform PEM -keyout {cert.key} -newkey {this.keyalg}:{this.keyparams}"
            if "-x509" in args:
                command += " -out {cert.pem} -passout file:\"{this.passpath}\"" # CA self-signed certificate
            else:
                command += " -passout file:\"{this.passpath}\""

        #
        # Signature parameters for "req -x509" (CA self-signed certificate) or
        # "x509 -req" (signing certificate request)
        #
        if (cmd == "req" and "-x509" in args) or (cmd == "x509" and "-req" in args):
            command += " -{this.sigalg}"

        #
        # Certificate request signature parameters
        #
        if cmd == "x509" and "-req" in args:
            command += " -CA {cacert.pem} -CAkey {cacert.key} -passin file:\"{this.passpath}\" -extensions ext " \
                       "-out {cert.pem}"

        #
        # Export certificate parameters
        #
        if cmd == "x509" and not "-req" in args:
            command += " -in {cert.pem}"
        elif cmd == self.keyalg or cmd == "pkcs8":
            command += " -in {cert.key} -passin file:\"{this.passpath}\""
            if password:
                command += " -passout file:\"{passpath}\""
        elif cmd == "pkcs12":
            command += " -in {cert.pem} -name {cert.alias} -export -passin file:\"{this.passpath}\""
            command += " -passout file:\"{passpath}\""

        command = command.format(cert = cert, cacert = self.cacert, this = self, passpath=passpath)
        try:
            return self.run(command, *args, **kargs)
        finally:
            for f in tmpfiles: # Remove temporary configuration files
                os.remove(f)
