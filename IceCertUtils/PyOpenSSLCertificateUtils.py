#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2003-2015 ZeroC, Inc. All rights reserved.
#
# This copy of Ice is licensed to you under the terms described in the
# ICE_LICENSE file included in this distribution.
#
# **********************************************************************

import os, random, tempfile

from CertificateUtils import DistinguishedName, Certificate, CertificateFactory, b, read, write
from OpenSSL import crypto

def setSubject(dn, subj):
    for k in [ "CN", "OU", "O", "L", "ST", "C", "emailAddress"]:
        if hasattr(dn, k):
            v = getattr(dn, k)
            if v:
                setattr(subj, k, v)

class PyOpenSSLCertificate(Certificate):
    def __init__(self, parent, dn, alias):
        Certificate.__init__(self, parent, dn, alias)
        self.key = None
        self.x509 = None

    def exists(self):
        return os.path.exists(os.path.join(self.parent.home, self.alias + ".p12"))

    def init(self, key, x509):
        self.key = key
        self.x509 = x509
        if not self.parent.rmHome:
            # Persist a PKCS12 file if not temporary home
            self.generatePKCS12()
        return self

    def load(self):
        self.p12 = os.path.join(self.parent.home, self.alias + ".p12")
        p12 = crypto.load_pkcs12(read(self.p12), self.parent.password)
        self.x509 = p12.get_certificate()
        self.key = p12.get_privatekey()
        return self

    def toText(self):
        return crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509)

    def savePKCS12(self, path, password="password", chain=True):
        p12 = crypto.PKCS12()
        p12.set_certificate(self.x509)
        p12.set_friendlyname(b(self.alias))

        if self.parent.cacert != self:
            p12.set_privatekey(self.key)
            if chain:
                p12.set_ca_certificates([self.parent.cacert.x509])

        write(path, p12.export(b(password)))
        return self

    def savePEM(self, path):
        with open(path, 'wb') as f: f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, self.x509))
        return self

    def saveDER(self, path):
        with open(path, 'wb') as f: f.write(crypto.dump_certificate(crypto.FILETYPE_ASN1, self.x509))
        return self

class PyOpenSSLCertificateFactory(CertificateFactory):
    def __init__(self, *args, **kargs):
        CertificateFactory.__init__(self, *args, **kargs)

        self.keyalg = crypto.TYPE_RSA if self.keyalg == "rsa" else crypto.TYPE_DSA

        self.cacert = PyOpenSSLCertificate(self, self.dn, "ca")
        if self.cacert.exists():
            self.cacert.load()
        else:
            # Generate the CA certificate
            key = crypto.PKey()
            key.generate_key(self.keyalg, self.keysize)

            req = crypto.X509Req()
            setSubject(self.dn, req.get_subject())

            req.set_pubkey(key)
            req.sign(key, self.sigalg)

            x509 = crypto.X509()
            x509.set_version(0x02)
            x509.set_serial_number(random.getrandbits(64))
            x509.gmtime_adj_notBefore(0)
            x509.gmtime_adj_notAfter(60 * 60 * 24 * self.validity)
            x509.set_issuer(req.get_subject())
            x509.set_subject(req.get_subject())
            x509.set_pubkey(req.get_pubkey())
            x509.add_extensions([
                crypto.X509Extension(b('basicConstraints'), False, b('CA:true')),
                crypto.X509Extension(b('subjectKeyIdentifier'), False, b('hash'), subject=x509),
            ])
            x509.sign(key, self.sigalg)

            self.cacert.init(key, x509)
            self.cacert.generatePEM()

    def create(self, alias, dn=None, ip=None, dns=None):

        if alias in self.certs:
            return self.certs[alias]

        cert = PyOpenSSLCertificate(self, dn or ip or alias, alias)
        if cert.exists():
            self.certs[alias] = cert.load()
            return cert

        subAltName = None
        if ip and dns:
            subAltName = "DNS: {dns}, IP: {ip}"
        elif ip:
            subAltName = "IP: {ip}"
        elif dns:
            subAltName = "DNS: {dns}"

        key = crypto.PKey()
        key.generate_key(self.keyalg, self.keysize)

        req = crypto.X509Req()
        setSubject(cert.dn, req.get_subject())

        req.set_pubkey(key)
        req.sign(key, self.sigalg)

        x509 = crypto.X509()
        x509.set_version(0x02)
        x509.set_serial_number(random.getrandbits(64))
        x509.gmtime_adj_notBefore(0)
        x509.gmtime_adj_notAfter(60 * 60 * 24 * self.validity)
        x509.set_issuer(self.cacert.x509.get_subject())
        x509.set_subject(req.get_subject())
        x509.set_pubkey(req.get_pubkey())

        extensions = [
            crypto.X509Extension(b('subjectKeyIdentifier'), False, b('hash'), subject=x509),
            crypto.X509Extension(b('authorityKeyIdentifier'), False, b('keyid:always,issuer:always'),
                                 issuer=self.cacert.x509),
            crypto.X509Extension(b('keyUsage'), False, b('nonRepudiation, digitalSignature, keyEncipherment'))
        ]
        if subAltName:
            extensions.append(crypto.X509Extension(b('subjectAltName'), False, b(subAltName.format(dns=dns,ip=ip))))
        x509.add_extensions(extensions)

        x509.sign(self.cacert.key, self.sigalg)

        self.certs[alias] = cert.init(key, x509)
        return cert
