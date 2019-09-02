#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

import os, subprocess, glob, tempfile

from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, d, read, opensslSupport, write

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

    def saveKey(self, path, password=None):
        if not opensslSupport:
            raise RuntimeError("No openssl support, add openssl to your PATH to export private keys")

        #
        # Write password to safe temporary file
        #
        passpath = None
        if password:
            (f, passpath) = tempfile.mkstemp()
            os.write(f, b(password))
            os.close(f)
        try:
            pem = self.parent.run("openssl", "pkcs12", "-nocerts", "-nodes", "-in " + self.generatePKCS12(),
                                  passin="file:" + self.parent.passpath,
                                  passout=("file:" + passpath) if passpath else None)

            (_, ext) = os.path.splitext(path)
            outform = "DER" if ext == ".der" or ext == ".crt" or ext == ".cer" else "PEM"
            self.parent.run("openssl", "pkcs8", "-nocrypt -topk8", outform=outform, out=path, stdin=pem)

        finally:
            if passpath:
                os.remove(passpath)
        return self

    def saveJKS(self, *args, **kargs):
        return Certificate.saveJKS(self, src=self.jks, *args, **kargs)

    def saveBKS(self, *args, **kargs):
        return Certificate.saveBKS(self, src=self.jks, *args, **kargs)

    def savePKCS12(self, path, password = None, chain=True, root=True, addkey=None):
        if not chain or not root:
            raise RuntimeError("can only export PKCS12 chain with root certificate")
        self.exportToKeyStore(path, password, addkey=addkey, src=self.jks)
        return self

    def savePEM(self, path, chain=True, root=False):
        text = self.keyTool("exportcert", "-rfc")
        if chain:
            parent = self.parent
            while parent if root else parent.parent:
                text += parent.cacert.keyTool("exportcert", "-rfc")
                parent = parent.parent
        write(path, text)
        return self

    def saveDER(self, path):
        self.keyTool("exportcert", file=path)
        return self

    def keyTool(self, *args, **kargs):
        return self.parent.keyTool(cert=self, *args, **kargs)

    def destroy(self):
        Certificate.destroy(self)
        if self.jks and os.path.exists(self.jks):
            os.remove(self.jks)

class KeyToolCertificateFactory(CertificateFactory):
    def __init__(self, *args, **kargs):
        CertificateFactory.__init__(self, *args, **kargs)

        # Transform key/signature algorithm to suitable values for keytool
        if not self.parent:
            self.keyalg = self.keyalg.upper()
            self.sigalg = self.sigalg.upper() + "with" + self.keyalg;

        # Create the CA self-signed certificate
        if not self.cacert.exists():
            cacert = self.cacert

            subAltName = cacert.getAlternativeName()
            issuerAltName = self.parent.cacert.getAlternativeName() if self.parent else None
            ext = "-ext bc:c" + \
                  ((" -ext san=" + subAltName) if subAltName else "") + \
                  ((" -ext ian=" + issuerAltName) if issuerAltName else "")

            if not self.parent:
                cacert.keyTool("genkeypair", ext, validity=self.validity, sigalg=self.sigalg)
            else:
                self.cacert = self.parent.cacert
                cacert.keyTool("genkeypair")
                pem = cacert.keyTool("gencert", ext, validity = self.validity, stdin=cacert.keyTool("certreq"))
                chain = ""
                parent = self.parent
                while parent:
                    chain += d(read(parent.cacert.pem))
                    parent = parent.parent
                cacert.keyTool("importcert", stdin=chain + d(pem))

            self.cacert = cacert
            self.cacert.generatePEM()

    def _createFactory(self, *args, **kargs):
        #
        # Intermediate CAs don't work well with keytool, they probably
        # can but at this point we don't want to spend more time on
        # this.
        #
        #return KeyToolCertificateFactory(*args, **kargs)
        raise NotImplementedError("KeyTool implementation doesn't support intermediate CAs")

    def _createChild(self, *args):
        return KeyToolCertificate(self, *args)

    def _generateChild(self, cert, serial, validity):
        subAltName = cert.getAlternativeName()
        issuerAltName = self.cacert.getAlternativeName()
        extendedKeyUsage = cert.getExtendedKeyUsage()

        # Generate a certificate/key pair
        cert.keyTool("genkeypair")

        # Create a certificate signing request
        req = cert.keyTool("certreq")

        ext = "-ext ku:c=dig,keyEnc" + \
              ((" -ext san=" + subAltName) if subAltName else "") + \
              ((" -ext ian=" + issuerAltName) if issuerAltName else "") + \
              ((" -ext eku=" + extendedKeyUsage) if extendedKeyUsage else "")

        # Sign the certificate with the CA
        if validity is None or validity > 0:
            pem = cert.keyTool("gencert", ext, validity = (validity or self.validity), stdin=req)
        else:
            pem = cert.keyTool("gencert", ext, startdate = "{validity}d".format(validity=validity), validity=-validity,
                               stdin=req)

        # Concatenate the CA and signed certificate and re-import it into the keystore
        chain = []
        parent = self
        while parent:
            chain.append(d(read(parent.cacert.pem)))
            parent = parent.parent
        cert.keyTool("importcert", stdin="".join(chain) + d(pem))

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
            command += " -rfc"

        command = command.format(cert = cert, cacert = self.cacert, this = self)
        return self.run(command, *args, **kargs)
