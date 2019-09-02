#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

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
        self.assertTrue(len(f.getCA().toText()) > 0)

        def testsave(path, fn):
            self.assertFalse(os.path.exists(path))
            fn(path)
            self.assertTrue(os.path.exists(path))
            os.remove(path)

        testsave("ca.pem", lambda path: f.getCA().save(path))
        testsave("ca-with-key.p12", lambda path: f.getCA().save(path, addkey=True))

        cert = f.create("test",validity=1)
        for s in ["test.pem", "test.p12"]:
            testsave(s, lambda path: cert.save(path, password="exportpassword"))
        if self.factory != "KeyToolCertificateFactory":
            testsave("test-nochain.p12", lambda path: cert.save(path, chain=False))
            testsave("test-noroot.p12", lambda path: cert.save(path, root=False))
        testsave("test_priv.pem", lambda path: cert.saveKey(path))
        testsave("test_priv_pass.pem", lambda path: cert.saveKey(path, password="test"))
        if keytoolSupport:
            testsave("test.jks", lambda path: cert.save(path))
            testsave("test.bks", lambda path: cert.save(path))
            testsave("test-ca.jks", lambda path: cert.save(path, caalias="cacert"))
            testsave("test-ca.bks", lambda path: cert.save(path, caalias="cacert"))

        f.destroy()

    def test_dn(self):
        Factory = vars(IceCertUtils)[self.factory]

        factory = Factory(cn="cnca", ou="ouca", o="oca", l="lca", st="stca", c="FR", emailAddress="eaca")
        cert = factory.create("cert", cn="cnk", ou="ouk", o="ok", l="lk", st="stk", c="EN", emailAddress="eak")

        for (c, s) in [(factory.getCA(), "ca"), (cert, "k")]:
            self.assertEqual(c.dn.CN, "cn%s" % s)
            self.assertEqual(c.dn.OU, "ou%s" % s)
            self.assertEqual(c.dn.O, "o%s" % s)
            self.assertEqual(c.dn.L, "l%s" % s)
            self.assertEqual(c.dn.ST, "st%s" % s)
            self.assertEqual(c.dn.C, "EN" if s == "k" else "FR")
            self.assertEqual(c.dn.emailAddress, "ea%s" % s)

            txt = c.toText()
            self.assertTrue(txt.find("CN=cn%s" % s) > 0)
            self.assertTrue(txt.find("OU=ou%s" % s) > 0)
            self.assertTrue(txt.find("O=o%s" % s) > 0)
            self.assertTrue(txt.find("L=l%s" % s) > 0)
            self.assertTrue(txt.find("ST=st%s" % s) > 0)
            self.assertTrue(txt.find("C=EN" if s == "k" else "C=FR") > 0)
            self.assertTrue(txt.find("=ea%s" % s) > 0)

        factory.destroy()

    def test_altName(self):
        Factory = vars(IceCertUtils)[self.factory]
        dn = IceCertUtils.DistinguishedName("CN")
        factory = Factory(dn=dn, ip="127.0.0.1", dns="ca.zeroc.com", email="ca@zeroc.com", uri="https://zeroc.com")
        cert = factory.create("cert", cn = "CERT", ip="127.0.0.2", dns="cert.zeroc.com", email="cert@zeroc.com")

        txt = factory.getCA().toText()
        self.assertTrue(txt.find("127.0.0.1") > 0)
        self.assertTrue(txt.find("ca.zeroc.com") > 0)
        self.assertTrue(txt.find("ca@zeroc.com") > 0)
        self.assertTrue(txt.find("https://zeroc.com") > 0)

        txt = cert.toText()
        self.assertTrue(txt.find("127.0.0.1") > 0)
        self.assertTrue(txt.find("ca.zeroc.com") > 0)
        self.assertTrue(txt.find("ca@zeroc.com") > 0)
        self.assertTrue(txt.find("https://zeroc.com") > 0)

        self.assertTrue(txt.find("127.0.0.2") > 0)
        self.assertTrue(txt.find("cert.zeroc.com") > 0)
        self.assertTrue(txt.find("cert@zeroc.com") > 0)

        factory.destroy()

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

        os.rmdir(self.home)

    def test_intermediate(self):
        if self.factory == "KeyToolCertificateFactory":
            # Intermediate certificate don't work well with KeyTool
            return

        f = vars(IceCertUtils)[self.factory](dn=IceCertUtils.DistinguishedName("CA"))
        im1 = f.createIntermediateFactory("im1")
        self.assertEqual(str(im1), "CN=im1")
        im2 = im1.createIntermediateFactory("im2")
        self.assertEqual(str(im2), "CN=im2")
        c1 = im2.create("test")
        self.assertEqual(str(c1), "CN=test")
        c2 = f.getIntermediateFactory("im1").getIntermediateFactory("im2").get("test")
        self.assertEqual(c1, c2)
        f.destroy()

    def test_params(self):

        f = vars(IceCertUtils)[self.factory](validity=10, keysize=3192, sigalg="sha512", keyalg="rsa")
        s = f.getCA().toText()
        self.assertTrue(s.find("sha512") > 0 or s.find("SHA512"))
        self.assertTrue(s.find("3192") > 0)

        f = vars(IceCertUtils)[self.factory](keyalg="dsa")
        s = f.getCA().toText()
        self.assertTrue(s.find("dsa") > 0 or s.find("DSA") > 0)

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
