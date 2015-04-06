#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

import os, subprocess, glob

from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, d, read

class KeyToolCertificate(Certificate):
    def __init__(self, *args):
        Certificate.__init__(self, *args)
        self.jks = os.path.join(self.parent.home, self.alias + ".jks")

    def exists(self):
        return os.path.exists(self.jks)

    def load(self):
        subject = self.toText()
        self.dn = DistinguishedName.parse(subject[subject.find(":") + 1:subject.find("\n")].strip())
        return self

    def toText(self):
        return d(self.parent.keyTool("printcert", "-v", stdin = self.keyTool("exportcert")))

    def saveJKS(self, path, password = "password", type = None, provider = None):
        self.exportToKeyStore(path, password, type, provider, self.jks)
        return self

    def savePKCS12(self, path, password = "password", chain=True):
        self.exportToKeyStore(path, password, "PKCS12", src=self.jks)
        return self

    def savePEM(self, path):
        self.keyTool("exportcert", "-rfc", file=path)
        return self

    def saveDER(self, path):
        self.keyTool("exportcert", file=path)
        return self

    def keyTool(self, *args, **kargs):
        return self.parent.keyTool(cert=self, *args, **kargs)

class KeyToolCertificateFactory(CertificateFactory):
    def __init__(self, *args, **kargs):
        CertificateFactory.__init__(self, *args, **kargs)

        # Transform key/signature algorithm to suitable values for keytool
        self.keyalg = self.keyalg.upper()
        self.sigalg = self.sigalg.upper() + "with" + self.keyalg;

        # Create the CA self-signed certificate
        self.cacert = self.get("ca")
        if not self.cacert:
            self.cacert = KeyToolCertificate(self, "ca", self.dn)
            self.certs["ca"] = self.cacert
            self.cacert.keyTool("genkeypair", ext="bc:c", validity=self.validity, sigalg=self.sigalg)
            self.cacert.generatePEM()

        self.dn = self.cacert.dn

    def _createChild(self, *args):
        return KeyToolCertificate(self, *args)

    def _generateChild(self, alias, dn=None, ip=None, dns=None):
        subAltName = None
        if ip and dns:
            subAltName = "san=DNS:{dns},IP:{ip}".format(ip=ip, dns=dns)
        elif ip:
            subAltName = "san=IP:{ip}".format(ip=ip)
        elif dns:
            subAltName = "san=DNS:{dns}".format(dns=dns)

        cert = KeyToolCertificate(self, alias, dn or ip or alias)

        # Generate a certificate/key pair
        cert.keyTool("genkeypair")

        # Create a certificate signing request
        req = cert.keyTool("certreq")

        # Sign the certificate with the CA
        pem = cert.keyTool("gencert", stdin=req, ext=subAltName)

        # Concatenate the CA and signed certificate and re-import it into the keystore
        chain = d(read(self.cacert.pem)) + d(pem)
        cert.keyTool("importcert", stdin=chain)

        return cert

    def list(self):
        return [os.path.splitext(os.path.basename(a))[0] for a in glob.glob(os.path.join(self.home, "*.jks"))]

    def keyTool(self, cmd, *args, **kargs):
        command = "keytool -noprompt -{cmd}".format(cmd = cmd)

        # Consume cert argument
        cert = kargs.get("cert", None)
        if cert: del kargs["cert"]

        # Setup -keystore, -storepass and -alias arguments
        if cmd in ["genkeypair", "exportcert", "certreq", "importcert"]:
            command += " -alias {cert.alias} -keystore {cert.jks} -storepass:file {this.passpath}"
        elif cmd in ["gencert"]:
            command += " -alias {cacert.alias} -keystore {cacert.jks} -storepass:file {this.passpath}"
        if cmd == "genkeypair":
            command += " -keypass:file {this.passpath} -keyalg {this.keyalg} -keysize {this.keysize} -dname \"{cert.dn}\""
        elif cmd == "certreq":
            command += " -sigalg {this.sigalg}"
        elif cmd == "gencert":
            command += " -validity {this.validity} -ext ku:c=dig,keyEnc -rfc"

        command = command.format(cert = cert, cacert = self.cacert, this = self)
        return self.run(command, *args, **kargs)
