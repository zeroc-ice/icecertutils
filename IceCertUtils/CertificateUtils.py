#!/usr/bin/env python
# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

import sys, os, shutil, subprocess, tempfile, random

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

def b(s):
    return s if sys.version_info[0] == 2 else s.encode("utf-8") if isinstance(s, str) else s

def read(p):
    with open(p, "r") as f: return f.read()

def write(p, data):
    with open(p, "wb") as f: f.write(data)

#
# Make sure keytool is available
#
keytoolSupport = True
if subprocess.call("keytool", shell=True, stdout=DEVNULL, stderr=DEVNULL) != 0:
    print("warning: couldn't find Java keytool, Java certificates won't be created")
    keytoolSupport = False

#
# Check if BouncyCastle support is available
#
bksSupport = False
if keytoolSupport:
    bksProvider = "org.bouncycastle.jce.provider.BouncyCastleProvider"
    p = subprocess.Popen("javap " + bksProvider, shell=True, stdout=DEVNULL, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.wait() != 0 or stderr.find("Error:") >= 0:
        print("warning: couldn't find Bouncy Castle provider, Android certificates won't be created")
    else:
        bksSupport = True

#
# Check if OpenSSL is available
#
opensslSupport = True
if subprocess.call("openssl version", shell=True, stdout=DEVNULL, stderr=DEVNULL) != 0:
    opensslSupport = False

#
# Check if pyOpenSSL is available
#
pyopensslSupport = False
try:
    import OpenSSL
    pyopensslSupport = True
except:
    pass

class DistinguishedName:

    def __init__(self, cn, ou = None, o = None, l = None, st = None, c = None, emailAddress=None, default = None):
        self.CN = cn
        self.OU = ou or (default.OU if default else "")
        self.O = o or (default.O if default else "")
        self.L = l or (default.L if default else "")
        self.ST = st or (default.ST if default else "")
        self.C = c or (default.C if default else "")
        self.emailAddress = emailAddress or (default.emailAddress if default else "")

    def __str__(self):
        return self.toString()

    def toString(self, sep = ","):
        s = ""
        for k in ["CN", "OU", "O", "L", "ST", "C", "emailAddress"]:
            if hasattr(self, k):
                v = getattr(self, k)
                if v:
                    v = v.replace(sep, "\\" + sep)
                    s += "{sep}{k}={v}".format(k = k, v = v, sep = "" if s == "" else sep)
        return s

class Certificate:
    def __init__(self, parent, dn, alias):
        self.parent = parent
        self.dn = dn if isinstance(dn, DistinguishedName) else DistinguishedName(dn, default=self.parent.dn)
        self.alias = alias
        self.pem = None
        self.p12 = None

    def __str__(self):
        return str(self.dn)

    def exists(self):
        return False

    def generatePEM(self):
        # Generate PEM for internal use
        if not self.pem:
            self.pem = os.path.join(self.parent.home, self.alias + ".pem")
        if not os.path.exists(self.pem):
            self.savePEM(self.pem)

    def generatePKCS12(self):
        # Generate PKCS12 for internal use
        if not self.p12:
            self.p12 = os.path.join(self.parent.home, self.alias + ".p12")
        if not os.path.exists(self.p12):
            self.savePKCS12(self.p12, password=self.parent.password)
        return self.p12

    def save(self, path, *args, **kargs):
        if os.path.exists(path):
            os.remove(path)
        (_, ext) = os.path.splitext(path)
        if ext == ".p12" or ext == ".pfx":
            return self.savePKCS12(path, *args, **kargs)
        elif ext == ".jks":
            return self.saveJKS(path, *args, **kargs)
        elif ext == ".bks":
            return self.saveBKS(path, *args, **kargs)
        elif ext == ".der":
            return self.saveDER(path)
        else:
            return self.savePEM(path)

    def savePKCS12(self, path):
        raise "not supported"

    def savePEM(self, path):
        raise "not supported"

    def saveDER(self, path):
        raise "not supported"

    def saveJKS(self, path, password="password", type="JKS", provider=None):
        self.exportToKeyStore(path, password, type, provider)
        return self

    def saveBKS(self, path, password="password"):
        if bksSupport:
            self.saveJKS(path, password, "BKS", bksProvider)
        return self

    def destroy(self):
        for f in [self.pem, self.p12]:
            if f and os.path.exists(f):
                os.remove(f)

    def exportToKeyStore(self, dest, password, type = None, provider = None, src = None):
        if not keytoolSupport:
            return

        def getType(path):
            (_, ext) = os.path.splitext(path)
            return { ".jks" : "JKS", ".bks": "BKS", ".p12": "PKCS12", ".pfx": "PKCS12" }[ext]

        # Write password to safe temporary file
        (f, passpath) = tempfile.mkstemp()
        os.write(f, b(password))
        os.close(f)

        try:
            if self != self.parent.cacert:
                args = {
                    "src": src or self.generatePKCS12(),
                    "srctype" : getType(src or self.generatePKCS12()),
                    "dest": dest,
                    "desttype": type or getType(dest),
                    "pass": passpath,
                }
                command = "keytool -noprompt -importkeystore -srcalias {cert.alias} "
                command += " -srckeystore {src} -srcstorepass:file {factory.passpath} -srcstoretype {srctype}"
                command += " -destkeystore {dest} -deststorepass:file {pass} -destkeypass:file {pass} "
                command += " -deststoretype {desttype}"
                if provider:
                    command += " -provider " + provider
                self.parent.run(command.format(cert=self, factory=self.parent, **args))
            else:
                args = {
                    "dest": dest,
                    "desttype": type or getType(dest),
                    "pass": passpath,
                }

            # Also add the CA certificate as a trusted certificate if JKS/BKS
            if args["desttype"] != "PKCS12":
                command = "keytool -noprompt -importcert -file {cert.pem} -alias {cert.alias}"
                command += " -keystore {dest} -storepass:file {pass} -storetype {desttype}"
                if provider:
                    command += " -provider " + provider
                self.parent.run(command.format(cert=self.parent.cacert, factory=self.parent, **args))
        finally:
            os.remove(passpath)

defaultDN = DistinguishedName("ZeroC IceCertUtils CA", "Ice", "ZeroC, Inc.", "Jupiter", "Florida", "US")

class CertificateFactory:
    def __init__(self, home=None, debug=None, dn=None, validity=1825, keysize=2048, keyalg="rsa", sigalg="sha256",
                 password = None):

        # Certificate generate parameters
        self.validity = validity
        self.keysize = keysize
        self.keyalg = keyalg
        self.sigalg = sigalg

        # Temporary directory for storing intermediate files
        self.rmHome = home is None
        self.home = home or tempfile.mkdtemp();
        self.dn = dn or defaultDN

        # The CA certificate and the array of certificates created with this factory
        self.cacert = None
        self.certs = {}

        # The password used to protect keys and key stores from the factory home directory
        self.passpath = os.path.join(self.home, "password")
        if not os.path.exists(self.passpath):
            self.password = password or str(random.getrandbits(128))
            with open(self.passpath, "w") as f: f.write(b(self.password))
        else:
            with open(self.passpath, "r") as f: self.password = f.read()

        self.debug = debug
        if self.debug:
            print("[debug] using %s implementation" % self.__class__.__name__)

    def __str__(self):
        return str(self.cacert or self.dn)

    def destroy(self, force=False):
        if self.rmHome or force:
            # Cleanup temporary directory
            if self.cacert:
                self.cacert.destroy()
            for (a,c) in self.certs.items():
                c.destroy()
            shutil.rmtree(self.home)

    def run(self, cmd, *args, **kargs):

        # Consume stdin argument
        stdin = kargs.get("stdin", None)
        if stdin : del kargs["stdin"]

        for a in args:
            cmd += " {a}".format(a = a)

        for (key, value) in kargs.items():
            if not value and value != "":
                continue
            value = str(value)
            if value == "" or value.find(' ') >= 0:
                cmd += " -{key} \"{value}\"".format(key=key, value=value)
            else:
                cmd += " -{key} {value}".format(key=key, value=value)

        if self.debug:
            print("[debug] %s" % cmd)

        p = subprocess.Popen(cmd,
                             shell = True,
                             stdin = subprocess.PIPE if stdin else None,
                             stdout = subprocess.PIPE,
                             stderr = subprocess.PIPE,
                             bufsize = 0)

        stdout, stderr = p.communicate(b(stdin))
        if p.wait() != 0:
            raise Exception("command failed: " + cmd + "\n" + (stderr or stdout))

        return stdout

def getDefaultImplementation():
    if pyopensslSupport:
        from IceCertUtils.PyOpenSSLCertificateUtils import PyOpenSSLCertificateFactory
        return PyOpenSSLCertificateFactory
    elif opensslSupport:
        from IceCertUtils.OpenSSLCertificateUtils import OpenSSLCertificateFactory
        return OpenSSLCertificateFactory
    elif keytoolSupport:
        from IceCertUtils.KeyToolCertificateUtils import KeyToolCertificateFactory
        return KeyToolCertificateFactory
    else:
        raise ImportError("couldn't find a certificate utility to generate certificates. If you have a JDK installed, please add the JDK bin directory to your PATH, if you have openssl installed make sure it's in your PATH. You can also install the pyOpenSSL package from the Python package repository if you don't have OpenSSL or a JDK installed.")
