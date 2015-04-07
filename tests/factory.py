#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

import sys, os, shutil, unittest, tempfile
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

import IceCertUtils
keytoolSupport = IceCertUtils.CertificateUtils.bksSupport
bksSupport = IceCertUtils.CertificateUtils.bksSupport

class TestFactory(unittest.TestCase):

    def setUp(self):
        self.factory = "CertificateFactory"
        self.home = "default"
        self.cn = "DefaultCA"

        self.cwd = os.getcwd()
        self.tmpdir = tempfile.mkdtemp()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self.cwd)
        os.rmdir(self.tmpdir)

    def test_transient(self):
        f = vars(IceCertUtils)[self.factory]()

        self.assertFalse(os.path.exists("ca.pem"))
        f.getCA().save("ca.pem")
        self.assertTrue(os.path.exists("ca.pem"))

        self.assertTrue(len(f.getCA().toText()) > 0)

        cert = f.create("test")

        for s in ["test.pem", "test.p12"]:
            self.assertFalse(os.path.exists(s))
            cert.save(s, password="exportpassword")
            self.assertTrue(os.path.exists(s))

        self.assertFalse(os.path.exists("test-nochain.p12"))
        cert.save("test-nochain.p12", chain=False)
        self.assertTrue(os.path.exists("test-nochain.p12"))

        self.assertFalse(os.path.exists("test_priv.pem"))
        cert.saveKey("test_priv.pem")
        self.assertTrue(os.path.exists("test_priv.pem"))

        for s in ["ca.pem", "test.pem", "test.p12", "test-nochain.p12", "test_priv.pem"]:
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

        self.assertEqual(str(f), "CN=" + self.cn)
        b = f.create("test")
        self.assertEqual(str(b), "CN=test")
        f.destroy()

        f = vars(IceCertUtils)[self.factory](home = self.home, password="testpass")
        a = f.get("test")
        certs = f.list()
        self.assertTrue("ca" in certs)
        self.assertTrue("test" in certs)
        self.assertEqual(str(a), "CN=test")

        self.assertEqual(b.toText(), a.toText())

        f.destroy(force=True)

class PyOpenSSLTestFactory(TestFactory):

    def setUp(self):
        TestFactory.setUp(self)
        self.factory = "PyOpenSSLCertificateFactory"
        self.home = "pyopenssl"
        self.cn = "PyOpenSSLCA"

class KeyToolTestFactory(TestFactory):

    def setUp(self):
        TestFactory.setUp(self)
        self.factory = "KeyToolCertificateFactory"
        self.home = "keytool"
        self.cn = "KeyToolCA"

class OpenSSLTestFactory(TestFactory):

    def setUp(self):
        TestFactory.setUp(self)
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

if __name__ == '__main__':
    unittest.main()
