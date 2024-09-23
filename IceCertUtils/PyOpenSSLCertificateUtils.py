#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

import os, random, glob, datetime

from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, d, read, write
from OpenSSL import crypto

def setSubject(dn, subj):
    for k in [ "CN", "OU", "O", "L", "ST", "C", "emailAddress"]:
        if hasattr(dn, k):
            v = getattr(dn, k)
            if v:
                setattr(subj, k, v)

class PyOpenSSLCertificate(Certificate):
    def __init__(self, *args):
        Certificate.__init__(self, *args)
        self.pem = os.path.join(self.parent.home, self.alias + ".pem")
        self.key = os.path.join(self.parent.home, self.alias + "_key.pem")
        self.pkey = None
        self.x509 = None

    def exists(self):
        return os.path.exists(self.pem)

    def init(self, pkey, x509):
        self.pkey = pkey
        self.x509 = x509
        self.generateKEY()
        self.generatePEM()
        return self

    def load(self):
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, read(self.pem))
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, read(self.key), b(self.parent.password))
        subject = cert.get_subject()
        self.dn = DistinguishedName(subject.commonName,
                                    subject.organizationalUnitName,
                                    subject.organizationName,
                                    subject.localityName,
                                    subject.stateOrProvinceName,
                                    subject.countryName,
                                    subject.emailAddress)
        return self.init(key, cert)

    def toText(self):
        s = """Version: %s
Serial Number: %s
Signature Algorithm: %s
Issuer: %s
Validity:
   Not before: %s
   Not after: %s
Subject: %s
Subject Public Key Size: %s
X509v3 extensions:""" % (self.x509.get_version() + 1,
                         self.x509.get_serial_number(),
                         self.x509.get_signature_algorithm(),
                         str(self.x509.get_issuer()).replace("<X509Name object '", "").replace("'>", ""),
                         datetime.datetime.strptime(d(self.x509.get_notBefore()), "%Y%m%d%H%M%SZ"),
                         datetime.datetime.strptime(d(self.x509.get_notAfter()), "%Y%m%d%H%M%SZ"),
                         str(self.x509.get_subject()).replace("<X509Name object '", "").replace("'>", ""),
                         str(self.x509.get_pubkey().bits()))
        for i in range(0, self.x509.get_extension_count()):
            ext = self.x509.get_extension(i)
            s += "\n    " + d(ext.get_short_name()).strip() + ":\n        " + str(ext).replace("\n", "\n        ")
        return s

    def getSubjectHash(self):
        return format(self.x509.subject_name_hash(), 'x')

    def saveKey(self, path, password=None):
        (_, ext) = os.path.splitext(path)
        type = crypto.FILETYPE_PEM
        if ext == ".der" or ext == ".crt" or ext == ".cer":
            type = crypto.FILETYPE_ASN1

        if password:
            write(path, crypto.dump_privatekey(type, self.pkey, self.parent.cipher, b(password)))
        else:
            write(path, crypto.dump_privatekey(type, self.pkey))
        return self

    def savePKCS12(self, path, password=None, chain=True, root=False, addkey=None):

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12, load_pem_private_key
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import NoEncryption


        def convert_pyopenssl_x509_to_cryptography(x509_obj):
            # Convert the PyOpenSSL X509 object to a PEM-encoded byte string, and load it into a
            # cryptography Certificate object.
            return x509.load_pem_x509_certificate(
                crypto.dump_certificate(crypto.FILETYPE_PEM, x509_obj),
                default_backend())

        def convert_pyopenssl_pkey_to_cryptography(private_key_obj):
            # Convert the PyOpenSSL PKey object to a PEM-encoded byte string, and load it into a
            # cryptography private key object
            return load_pem_private_key(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key_obj),
                password=None,
                backend=default_backend())

        if addkey is None:
            addkey = self != self.parent.cacert

        chain_certs = []
        if chain:
            parent = self.parent
            while parent if root else parent.parent:
                chain_certs.append(parent.cacert.x509)
                parent = parent.parent


        if password:
            encryption_password = password.encode('utf-8')  # Correctly encode the password
            # With OpenSSL 3.0.0+ the defaults for encryption when serializing PKCS12 have changed and some
            # versions of Windows and macOS will not be able to read the new format.
            encryption = (
                PrivateFormat.PKCS12.encryption_builder().
                key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
                hmac_hash(hashes.SHA1())).build(encryption_password)
        else:
            encryption = NoEncryption()

        pkcs12_data = pkcs12.serialize_key_and_certificates(
            name = self.alias.encode('utf-8') if self.alias else None,
            key=convert_pyopenssl_pkey_to_cryptography(self.pkey) if addkey else None,
            cert=convert_pyopenssl_x509_to_cryptography(self.x509),
            cas=[convert_pyopenssl_x509_to_cryptography(cert) for cert in chain_certs] if len(chain_certs) > 0 else None,
            encryption_algorithm=encryption
        )
        write(path, pkcs12_data)
        return self

    def savePEM(self, path, chain=True, root=False):
        text = crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509)
        if chain:
            parent = self.parent
            while parent if root else parent.parent:
                text += crypto.dump_certificate(crypto.FILETYPE_PEM, parent.cacert.x509)
                parent = parent.parent
        write(path, text)
        return self

    def saveDER(self, path):
        write(path, crypto.dump_certificate(crypto.FILETYPE_ASN1, self.x509))
        return self

    def generateKEY(self):
        if not os.path.exists(self.key):
            write(self.key, crypto.dump_privatekey(crypto.FILETYPE_PEM, self.pkey, self.parent.cipher,
                                                   b(self.parent.password)))

    def destroy(self):
        Certificate.destroy(self)
        if os.path.exists(self.key):
            os.remove(self.key)

class PyOpenSSLCertificateFactory(CertificateFactory):
    def __init__(self, *args, **kargs):
        CertificateFactory.__init__(self, *args, **kargs)

        if not self.parent:
            self.keyalg = crypto.TYPE_RSA if self.keyalg == "rsa" else crypto.TYPE_DSA

        self.cipher = "DES-EDE3-CBC" # Cipher used to encode the private key

        if not self.cacert.exists():
            # Generate the CA certificate
            key = crypto.PKey()
            key.generate_key(self.keyalg, self.keysize)

            req = crypto.X509Req()
            setSubject(self.cacert.dn, req.get_subject())

            req.set_pubkey(key)
            req.sign(key, self.sigalg)

            x509 = crypto.X509()
            x509.set_version(0x02)
            x509.set_serial_number(random.getrandbits(64))

            x509.gmtime_adj_notBefore(0)
            x509.gmtime_adj_notAfter(60 * 60 * 24 * self.validity)
            x509.set_subject(req.get_subject())
            x509.set_pubkey(req.get_pubkey())
            extensions = [
                crypto.X509Extension(b('basicConstraints'), False, b('CA:true')),
                crypto.X509Extension(b('subjectKeyIdentifier'), False, b('hash'), subject=x509),
                crypto.X509Extension(b('keyUsage'), False, b('digitalSignature,keyCertSign,cRLSign'))
            ]

            if self.extendedKeyUsage:
                extensions.append(crypto.X509Extension(b('extendedKeyUsage'), False, b(self.extendedKeyUsage)))

            if self.parent:
                if self.parent.crlDistributionPoints:
                    extensions.append(crypto.X509Extension(b('crlDistributionPoints'),
                                                           False,
                                                           b("URI:" + self.parent.crlDistributionPoints)))

                authorityInfoAccess = []
                if self.parent.ocspResponder:
                    authorityInfoAccess.append("OCSP;URI:{}".format(self.parent.ocspResponder))

                if self.parent.caIssuers:
                    authorityInfoAccess.append("caIssuers;URI:{}".format(self.parent.caIssuers))

                if len(authorityInfoAccess) > 0:
                    authorityInfoAccess = bytes(",".join(authorityInfoAccess), 'utf-8')
                    extensions.append(crypto.X509Extension(b('authorityInfoAccess'), False, authorityInfoAccess))

            subjectAltName = self.cacert.getAlternativeName()
            if subjectAltName:
                extensions.append(crypto.X509Extension(b('subjectAltName'), False, b(subjectAltName)))

            if self.parent:
                extensions.append(crypto.X509Extension(b('authorityKeyIdentifier'), False,
                                                       b('keyid:always,issuer:always'), issuer=self.parent.cacert.x509))
                if self.parent.cacert.getAlternativeName():
                    extensions.append(crypto.X509Extension(b('issuerAltName'), False, b("issuer:copy"),
                                                           issuer=self.parent.cacert.x509))

            x509.add_extensions(extensions)

            if self.parent:
                x509.set_issuer(self.parent.cacert.x509.get_subject())
                x509.sign(self.parent.cacert.pkey, self.sigalg)
            else:
                x509.set_issuer(req.get_subject())
                x509.sign(key, self.sigalg)

            self.cacert.init(key, x509)

    def _createFactory(self, *args, **kargs):
        return PyOpenSSLCertificateFactory(*args, **kargs)

    def _createChild(self, *args):
        return PyOpenSSLCertificate(self, *args)

    def _generateChild(self, cert, serial, validity):
        key = crypto.PKey()
        key.generate_key(self.keyalg, self.keysize)

        req = crypto.X509Req()
        setSubject(cert.dn, req.get_subject())

        req.set_pubkey(key)
        req.sign(key, self.sigalg)

        x509 = crypto.X509()
        x509.set_version(0x02)
        x509.set_serial_number(serial or random.getrandbits(64))
        if validity is None or validity > 0:
            x509.gmtime_adj_notBefore(0)
            x509.gmtime_adj_notAfter(60 * 60 * 24 * (validity or self.validity))
        else:
            x509.gmtime_adj_notBefore(60 * 60 * 24 * validity)
            x509.gmtime_adj_notAfter(0)

        x509.set_issuer(self.cacert.x509.get_subject())
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())

        extensions = [
            crypto.X509Extension(b('subjectKeyIdentifier'), False, b('hash'), subject=x509),
            crypto.X509Extension(b('authorityKeyIdentifier'), False, b('keyid:always,issuer:always'),
                                 issuer=self.cacert.x509),
            crypto.X509Extension(b('keyUsage'), False, b('nonRepudiation, digitalSignature, keyEncipherment'))
        ]

        if self.crlDistributionPoints:
            extensions.append(crypto.X509Extension(b('crlDistributionPoints'),
                                                   False,
                                                   b("URI:" + self.crlDistributionPoints)))

        authorityInfoAccess = []
        if self.ocspResponder:
            authorityInfoAccess.append("OCSP;URI:{}".format(self.ocspResponder))

        if self.caIssuers:
            authorityInfoAccess.append("caIssuers;URI:{}".format(self.caIssuers))

        if len(authorityInfoAccess) > 0:
            authorityInfoAccess = bytes(",".join(authorityInfoAccess), 'utf-8')
            extensions.append(crypto.X509Extension(b('authorityInfoAccess'), False, authorityInfoAccess))

        subAltName = cert.getAlternativeName()
        if subAltName:
            extensions.append(crypto.X509Extension(b('subjectAltName'), False, b(subAltName)))
        if self.cacert.getAlternativeName():
            extensions.append(crypto.X509Extension(b('issuerAltName'), False, b("issuer:copy"),issuer=self.cacert.x509))

        extendedKeyUsage = cert.getExtendedKeyUsage()
        if extendedKeyUsage:
            extensions.append(crypto.X509Extension(b('extendedKeyUsage'),False,b(extendedKeyUsage)))

        x509.add_extensions(extensions)

        x509.sign(self.cacert.pkey, self.sigalg)

        return cert.init(key, x509)

    def list(self):
        return [os.path.basename(a).replace("_key.pem","") for a in glob.glob(os.path.join(self.home, "*_key.pem"))]
