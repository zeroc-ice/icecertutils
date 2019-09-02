#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

import sys, os, shutil, subprocess, tempfile, random, re, atexit

try:
    from subprocess import DEVNULL
except ImportError:
    DEVNULL = open(os.devnull, 'wb')

def b(s):
    return s if sys.version_info[0] == 2 else s.encode("utf-8") if isinstance(s, str) else s

def d(s):
    return s if sys.version_info[0] == 2 else s.decode("utf-8") if isinstance(s, bytes) else s

def read(p):
    with open(p, "r") as f: return f.read()

def write(p, data):
    with open(p, "wb") as f: f.write(data)

#
# Make sure keytool is available
#
keytoolSupport = True
if subprocess.call("keytool", shell=True, stdout=DEVNULL, stderr=DEVNULL) != 0:
    keytoolSupport = False

#
# Check if BouncyCastle support is available
#
bksSupport = False
if keytoolSupport:
    bksProvider = "org.bouncycastle.jce.provider.BouncyCastleProvider"
    p = subprocess.Popen("javap " + bksProvider, shell=True, stdout=DEVNULL, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.wait() == 0 and d(stderr).find("Error:") == -1:
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
    v = re.match(r"([0-9]+)\.([0-9]+)", OpenSSL.__version__)
    # Require pyOpenSSL >= 0.13
    pyopensslSupport = (int(v.group(1)) * 100 + int(v.group(2))) >= 13
except:
    pass

SPLIT_PATTERN = re.compile(r'''((?:[^,"']|"[^"]*"|'[^']*')+)''')

class DistinguishedName:

    def __init__(self, CN, OU = None, O = None, L = None, ST = None, C = None, emailAddress = None, default = None):
        self.CN = CN
        self.OU = OU or (default.OU if default else "")
        self.O = O or (default.O if default else "")
        self.L = L or (default.L if default else "")
        self.ST = ST or (default.ST if default else "")
        self.C = C or (default.C if default else "")
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

    @staticmethod
    def parse(str):
        args = {}
        for m in SPLIT_PATTERN.split(str)[1::2]:
            p = m.find("=")
            if p != -1:
                v = m[p+1:].strip()
                if v.startswith('"') and v.endswith('"'):
                    v = v[1:-1]
                args[m[0:p].strip().upper()] = v
        if "EMAILADDRESS" in args:
            args["emailAddress"] = args["EMAILADDRESS"]
            del args["EMAILADDRESS"]
        return DistinguishedName(**args)

class Certificate:
    def __init__(self, parent, alias, dn=None, altName=None, extendedKeyUsage=None):
        self.parent = parent
        self.dn = dn
        self.altName = altName or {}
        self.extendedKeyUsage = extendedKeyUsage
        self.alias = alias
        self.pem = None

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

    def generatePKCS12(self, root=True):
        # Generate PKCS12 for internal use
        path = os.path.join(self.parent.home, self.alias + (".p12" if root else "-noroot.p12"))
        if not os.path.exists(path):
            self.savePKCS12(path, password=self.parent.password, chain=True, root=root, addkey=True)
        return path

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
        elif ext in [".der", ".cer", ".crt"]:
            return self.saveDER(path)
        elif ext == ".pem":
            return self.savePEM(path)
        else:
            raise RuntimeError("unknown certificate extension `{0}'".format(ext))

    def getSubjectHash(self):
        raise NotImplementedError("getSubjectHash")

    def saveKey(self, path, password=None):
        raise NotImplementedError("saveKey")

    def savePKCS12(self, path):
        raise NotImplementedError("savePKCS12")

    def savePEM(self, path):
        raise NotImplementedError("savePEM")

    def saveDER(self, path):
        raise NotImplementedError("saveDER")

    def saveJKS(self, *args, **kargs):
        self.exportToKeyStore(*args, **kargs)
        return self

    def saveBKS(self, *args, **kargs):
        if not bksSupport:
            raise RuntimeError("No BouncyCastle support, you need to install the BouncyCastleProvider with your JDK")
        self.exportToKeyStore(provider=bksProvider, *args, **kargs)
        return self

    def destroy(self):
        for f in [os.path.join(self.parent.home, self.alias + ".pem"),
                  os.path.join(self.parent.home, self.alias + ".p12"),
                  os.path.join(self.parent.home, self.alias + "-noroot.p12")]:
            if f and os.path.exists(f):
                os.remove(f)

    def exportToKeyStore(self, dest, password=None, alias=None, addkey=None, caalias=None, chain=True, root=False,
                         provider=None, src=None):
        if addkey is None:
            addkey = self != self.parent.cacert

        if not keytoolSupport:
            raise RuntimeError("No keytool support, add keytool from your JDK bin directory to your PATH")

        def getType(path):
            (_, ext) = os.path.splitext(path)
            return { ".jks" : "JKS", ".bks": "BKS", ".p12": "PKCS12", ".pfx": "PKCS12" }[ext]

        # Write password to safe temporary file
        (f, passpath) = tempfile.mkstemp()
        os.write(f, b(password or "password"))
        os.close(f)

        try:
            #
            # Add the CA certificate as a trusted certificate if requests
            #
            if caalias:
                args = {
                    "dest": dest,
                    "desttype": getType(dest),
                    "pass": passpath,
                    "caalias": caalias,
                    "cert": self.parent.cacert,
                    "factory": self.parent
                }
                command = "keytool -noprompt -importcert -file {cert.pem} -alias {caalias}"
                command += " -keystore {dest} -storepass:file {pass} -storetype {desttype}"
                self.parent.run(command.format(**args), provider=provider)

            if not src:
                src = self.generatePKCS12(root)

            if addkey:
                args = {
                    "src": src,
                    "srctype" : getType(src),
                    "dest": dest,
                    "desttype": getType(dest),
                    "destalias": alias or self.alias,
                    "pass": passpath,
                    "cert": self,
                    "factory": self.parent,
                }
                command = "keytool -noprompt -importkeystore -srcalias {cert.alias} "
                command += " -srckeystore {src} -srcstorepass:file {factory.passpath} -srcstoretype {srctype}"
                command += " -destkeystore {dest} -deststorepass:file {pass} -destkeypass:file {pass} "
                command += " -destalias {destalias} -deststoretype {desttype}"
            else:
                args = {
                    "dest": dest,
                    "destalias": alias or self.alias,
                    "desttype": getType(dest),
                    "pass": passpath,
                    "cert": self,
                    "factory": self.parent
                }
                command = "keytool -noprompt -importcert -file {cert.pem} -alias {destalias}"
                command += " -keystore {dest} -storepass:file {pass} -storetype {desttype} "

            self.parent.run(command.format(**args), provider=provider)
        finally:
            os.remove(passpath)

    def getAlternativeName(self):
        items = []
        for k, v in self.altName.items():
            items.append("{0}:{1}".format(k, v))
        return ",".join(items) if len(items) > 0 else None

    def getExtendedKeyUsage(self):
        return self.extendedKeyUsage

defaultDN = DistinguishedName("ZeroC IceCertUtils CA", "Ice", "ZeroC, Inc.", "Jupiter", "Florida", "US",
                              emailAddress="info@zeroc.com")

def getDNAndAltName(alias, defaultDN, dn=None, altName=None, **kargs):
    def consume(kargs, keys):
        args = {}
        for k in keys:
            if k in kargs:
                args[k] = kargs[k]
                del kargs[k]
            elif k.upper() in kargs:
                args[k] = kargs[k.upper()]
                del kargs[k.upper()]
            elif k.lower() in kargs:
                args[k] = kargs[k.lower()]
                del kargs[k.lower()]

            if k in args and args[k] is None:
                del args[k]

        return (kargs, args)

    if not altName:
        # Extract alternative name arguments
        (kargs, altName) = consume(kargs, ["IP", "DNS", "email", "URI"])

    if not dn:
        # Extract distinguished name arguments
        (kargs, dn) = consume(kargs, ["CN", "OU", "O", "L", "ST", "C", "emailAddress"])
        if len(dn) > 0:
            dn = DistinguishedName(default=defaultDN, **dn)
        else:
            for k in ["ip", "dns", "email"]:
                if k in altName:
                    dn = DistinguishedName(altName[k], default=defaultDN)
                    break
            else:
                dn = DistinguishedName(alias, default=defaultDN)

    return (kargs, dn, altName)

class CertificateFactory:
    def __init__(self, home=None, debug=None, validity=None, keysize=None, keyalg=None, sigalg=None, password=None,
                 parent=None, *args, **kargs):

        (kargs, dn, altName) = getDNAndAltName("ca", defaultDN, **kargs)
        if len(kargs) > 0:
            raise TypeError("unexpected arguments")

        self.parent = parent;

        # Certificate generate parameters
        self.validity = validity or (parent.validity if parent else 825)
        self.keysize = keysize or (parent.keysize if parent else 2048)
        self.keyalg = keyalg or (parent.keyalg if parent else "rsa")
        self.sigalg = sigalg or (parent.sigalg if parent else "sha256")

        # Temporary directory for storing intermediate files
        self.rmHome = home is None
        self.home = home or tempfile.mkdtemp();

        self.certs = {}
        self.factories = {}

        # The password used to protect keys and key stores from the factory home directory
        self.password = password or parent.password if parent else "password"
        if parent:
            self.passpath = parent.passpath
        else:
            (f, self.passpath) = tempfile.mkstemp()
            os.write(f, b(self.password))
            os.close(f)

            @atexit.register
            def rmpass():
                if os.path.exists(self.passpath):
                    os.remove(self.passpath)

        self.debug = debug or (parent.debug if parent else False)
        if self.debug:
            print("[debug] using %s implementation" % self.__class__.__name__)

        # Load the CA certificate if it exists
        self.cacert = self._createChild("ca", dn or defaultDN, altName)
        self.certs["ca"] = self.cacert
        if self.cacert.exists():
            self.cacert.load()

    def __str__(self):
        return str(self.cacert)

    def create(self, alias, serial=None, validity=None, extendedKeyUsage=None, *args, **kargs):
        cert = self.get(alias)
        if cert:
            cert.destroy() # Remove previous certificate

        (kargs, dn, altName) = getDNAndAltName(alias, self.cacert.dn, **kargs)
        if len(args) > 0 or len(kargs) > 0:
            raise TypeError("unexpected arguments")

        cert = self._createChild(alias, dn, altName, extendedKeyUsage)
        self._generateChild(cert, serial, validity)
        self.certs[alias] = cert
        return cert

    def get(self, alias):
        if alias in self.certs:
            return self.certs[alias]
        cert = self._createChild(alias)
        if cert.exists():
            self.certs[alias] = cert.load()
            return cert
        else:
            return None

    def getCA(self):
        return self.cacert

    def createIntermediateFactory(self, alias, *args, **kargs):
        factory = self.getIntermediateFactory(alias)
        if factory:
            factory.destroy(force = True)

        home = os.path.join(self.home, alias)
        os.mkdir(home)

        (kargs, dn, altName) = getDNAndAltName(alias, self.cacert.dn, **kargs)
        if len(args) > 0 or len(kargs) > 0:
            raise TypeError("unexpected arguments")

        factory = self._createFactory(home = home, dn = dn, altName=altName, parent = self)
        self.factories[alias] = factory
        return factory

    def getIntermediateFactory(self, alias):
        if alias in self.factories:
            return self.factories[alias]

        home = os.path.join(self.home, alias)
        if not os.path.isdir(home):
            return None

        factory = self._createFactory(home = home, parent = self)
        self.factories[alias] = factory
        return factory

    def destroy(self, force=False):
        if self.rmHome:
            # Cleanup temporary directory
            shutil.rmtree(self.home)
        elif force:
            if os.path.exists(self.passpath):
                os.remove(self.passpath)
            for (a,c) in self.certs.items():
                c.destroy()

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
            raise Exception("command failed: " + cmd + "\n" + d(stderr or stdout))

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
