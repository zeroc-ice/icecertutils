#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

import sys, os, shutil, unittest
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

def test(c):
    if not c:
        raise Exception("test failed")

def testEq(l, r):
    if l != r:
        raise Exception("test failed: {l} != {r}".format(l=l, r=r))

import IceCertUtils
keytoolSupport = IceCertUtils.CertificateUtils.bksSupport
bksSupport = IceCertUtils.CertificateUtils.bksSupport

class TestFactory(unittest.TestCase):

    def setUp(self):
        self.factory = "CertificateFactory"
        self.home = "default"
        self.cn = "DefaultCA"

    def test_transient(self):
        f = vars(IceCertUtils)[self.factory]()
        cert = f.create("test")

        for s in ["test.pem", "test.p12"]:
            cert.save(s, password="exportpassword")
        cert.save("test-nochain.p12", chain=False)
        for s in ["test.pem", "test.p12", "test-nochain.p12"]:
            os.remove(s)

        if keytoolSupport:
            cert.save("test.jks")
            os.remove("test.jks")

        if bksSupport:
            cert.save("test.bks")
            os.remove("test.bks")
        f.destroy()

    def test_persistent(self):

        if os.path.exists(self.home):
            shutil.rmtree(self.home)
        os.mkdir(self.home)

        f = vars(IceCertUtils)[self.factory](home = self.home, dn = IceCertUtils.DistinguishedName(self.cn),
                                             password="testpass")
        self.assertEquals(str(f), "CN=" + self.cn)
        b = f.create("test")
        self.assertEquals(str(b), "CN=test")
        f.destroy()

        f = vars(IceCertUtils)[self.factory](home = self.home, dn = IceCertUtils.DistinguishedName(self.cn))
        a = f.create("test")
        self.assertEquals(str(a), "CN=test")

        self.assertEquals(b.toText(), a.toText())

        f.destroy(force=True)

class PyOpenSSLTestFactory(TestFactory):

    def setUp(self):
        self.factory = "PyOpenSSLCertificateFactory"
        self.home = "pyopenssl"
        self.cn = "PyOpenSSLCA"

class KeyToolTestFactory(TestFactory):

    def setUp(self):
        self.factory = "KeyToolCertificateFactory"
        self.home = "keytool"
        self.cn = "KeyToolCA"

class OpenSSLTestFactory(TestFactory):

    def setUp(self):
        self.factory = "OpenSSLCertificateFactory"
        self.home = "openssl"
        self.cn = "OpenSSLCA"

testSuite = unittest.TestSuite()
if IceCertUtils.CertificateUtils.pyopensslSupport:
    testSuite.addTests(unittest.TestLoader().loadTestsFromTestCase(PyOpenSSLTestFactory))
if IceCertUtils.CertificateUtils.keytoolSupport:
    testSuite.addTest(unittest.TestLoader().loadTestsFromTestCase(KeyToolTestFactory))
if IceCertUtils.CertificateUtils.opensslSupport:
    testSuite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenSSLTestFactory))

cwd = os.getcwd()
os.chdir(os.path.dirname(__file__))

if __name__ == '__main__':
    unittest.main()

os.chdir(cwd)
