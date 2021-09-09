#!/usr/bin/env python
#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

import os, sys, getopt, tempfile, getpass, shutil, socket, uuid, IceCertUtils

def usage():
    print("usage: " + sys.argv[0] + " [--verbose --help --capass <pass>] init create list show export")
    print("")
    print("The iceca command manages a small certificate authority to create and sign")
    print("certificates for Ice clients or servers.")
    print("")
    print("Commands:")
    print("init     Initialize the certificate authority database")
    print("create   Create and sign a certificate/key pair")
    print("list     List the created certificates")
    print("show     Show a given certificate")
    print("export   Export a given certificate")
    print("")
    sys.exit(1)

def b(s):
    return s if sys.version_info[0] == 2 else s.encode("utf-8") if isinstance(s, str) else s

def question(message, expected = None):
   sys.stdout.write(message)
   sys.stdout.write(' ')
   sys.stdout.flush()
   choice = sys.stdin.readline().strip()
   if expected:
      return choice in expected
   else:
      return choice

def parseArgs(script, min, max, shortopts, longopts, usage):
   try:
      opts, args = getopt.getopt(sys.argv[script+1:], shortopts, longopts)
   except getopt.GetoptError:
      print("usage: " + sys.argv[script] + " " + usage)
      sys.exit(1)

   if len(args) < min or len(args) > max:
      print("usage: " + sys.argv[script] + " " + usage)
      sys.exit(1)

   options = {}
   for o, a in opts:
      options[o[(2 if o.startswith("--") else 1):]] = a

   return (options, args)

def getCertificateAuthority(home, cafile, capass, verbose):
   if not os.path.exists(cafile):
      print(sys.argv[0] + ": the CA is not initialized, run iceca init")
      sys.exit(1)

   if not capass:
      if os.path.exists(os.path.join(home, "capass")):
         with open(os.path.join(home, "capass")) as f: capass = f.read()
      else:
         capass = getpass.getpass("Enter the CA passphrase:")
   return IceCertUtils.CertificateFactory(home=home, debug=verbose, password=capass)

def init(script, home, cafile, capass, verbose):
   opts, _ = parseArgs(script, 0, 0, "", ["overwrite", "no-capass"], "[--overwrite --no-capass]\n"
   "\n"
   "Initializes the certificate authority database.\n"
   "\nOptions:\n"
   "--overwrite    Overwrite the existing CA database\n"
   "--no-capass    Don't protect the CA with a password\n")

   print("This script will initialize your organization's Certificate Authority.")
   print('The CA database will be created in "%s"' % home)

   if "overwrite" in opts:
      # If the CA exists then destroy it.
      if os.path.exists(cafile):
         if not question("Warning: running this command will destroy your existing CA setup!\n"
                         "Do you want to continue? (y/n)", ['y', 'Y']):
            sys.exit(1)
         shutil.rmtree(home)
      if os.path.exists(os.path.join(home, "capass")):
         os.remove(os.path.join(home, "capass"))

   #
   # Check that the cafile doesn't exist
   #
   if os.path.exists(cafile):
      print(sys.argv[0] + ": CA has already been initialized.")
      print("Use the --overwrite option to re-initialize the database.")
      sys.exit(1)

   try:
      os.makedirs(home)
   except OSError:
      pass

   # Construct the DN for the CA certificate.
   DNelements = {
      'C': "Country name",
      'ST':"State or province name",
      'L': "Locality",
      'O': "Organization name",
      'OU':"Organizational unit name",
      'CN':"Common name",
      'emailAddress': "Email address"
   }

   dn = IceCertUtils.DistinguishedName("Ice CertUtils CA")
   while True:
      print("")
      print("The subject name for your CA will be " + str(dn))
      print("")
      if question("Do you want to keep this as the CA subject name? (y/n) [y]", ['n', 'N']):
         for k,v in DNelements.items():
            v = question(v + ": ")
            if k == 'C' and len(v) > 2:
               print("The contry code can't be longer than 2 characters")
               continue
            setattr(dn, k, v)

      else:
         break

   if "no-capass" in opts:
      # If the user doesn't want a password, we save a random password under the CA home directory.
      capass = str(uuid.uuid4())
      with open(os.path.join(home, "capass"), "wb") as f: f.write(b(capass))
   elif not capass:
      capass = ""
      while True:
         capass = getpass.getpass("Enter the passphrase to protect the CA:")
         if len(capass) < 6:
            print("The CA passphrase must be at least 6 characters long")
         else:
            break

   IceCertUtils.CertificateFactory(home=home, debug=verbose, dn=dn, password=capass)

   print("The CA is initialized in " + home)

def create(script, factory):

   opts, args = parseArgs(script, 1, 2, "", ["ip=", "dns="], "[--ip=<ip>] [--dns=<dns>] <alias> [<common-name>]\n"
   "\n"
   "Creates and signs a certificate. A certificate is identified by its alias. If no\n"
   "common name is specified, the alias is used as the common name.\n"
   "\nOptions:\n"
   "--ip    Optional IP subject alternative name field\n"
   "--dns   Optional DNS subject alternative name field\n"
   "--eku   Optional Extended Key Usage\n")

   alias = args[0]
   commonName = len(args) == 2 and args[1] or alias
   cert = factory().create(alias, cn=commonName, ip=opts.get("ip", None), dns=opts.get("dns", None))
   print("Created `%s' certificate `%s'" % (alias, str(cert)))

def export(script, factory):

   opts, args = parseArgs(script, 1, 1, "", ["password=", "alias="], "[--password <password>] [--alias <alias>] path\n"
   "\n"
   "Export a certificate from the CA to the given file path. If --alias isn't\n"
   "specified, the filename indicates which certificate to export. The file\n"
   "extension also specifies the export format for the certificate. Supported\n"
   "formats are:\n\n"
   " PKCS12 (.p12, .pfx)\n"
   " PEM (.pem)\n"
   " DER (.der, .cer, .crt)\n"
   " JKS (.jks, requires keytool to be in the PATH)\n"
   " BKS (.bks, requires keytool and support for the BouncyCastle provider)\n"
   "\nOptions:\n"
   "--password  The password to use for protecting the exported certificate\n"
   "--alias     The alias of the certificate to export\n")

   path = args[0]
   alias = opts.get("alias", os.path.splitext(os.path.basename(path))[0])

   passphrase = opts.get("password", None)
   if not passphrase and os.path.splitext(os.path.basename(path))[1] in [".p12", ".jks", ".bks"]:
      passphrase = getpass.getpass("Enter the export passphrase:")

   cert = factory().get(alias)
   if cert:
      cert.save(path, password=passphrase)
      print("Exported certificate `{alias}' to `{path}'".format(alias=alias, path=path))
   else:
      print("Couldn't find certificate `%s'" % alias)

def list(script, factory):

   opts, args = parseArgs(script, 0, 0, "", [], "\n"
   "\n"
   "List aliases for the certificates created with this CA.\n")

   print("Certificates: %s" % factory().list())

def show(script, factory):

   opts, args = parseArgs(script, 1, 1, "", [], "<alias>\n"
   "\n"
   "Print out the certificate associated to the given alias.\n")

   alias = args[0]
   cert = factory().get(alias)
   if cert:
      print("Certificate `%s':\n%s" % (alias, cert.toText()))
   else:
      print("Couldn't find certificate `%s'" % alias)

def main():

    if len(sys.argv) == 1:
        usage()

    home = os.getenv("ICE_CA_HOME")
    if home is None:

       if sys.platform == "win32" or sys.platform[:6] == "cygwin":
          home = os.getenv("LOCALAPPDATA")
       else:
          home = os.getenv("HOME")

       if home is None:
          print("Set ICE_CA_HOME to specify the location of the CA database")
          sys.exit(1)

       home = os.path.join(home, ".iceca")

    home = os.path.normpath(home)
    cafile = os.path.join(home, "ca.pem")

    #
    # Work out the position of the script.
    #
    script = 1
    while script < len(sys.argv) and sys.argv[script].startswith("--"):
        script = script + 1
    if script >= len(sys.argv):
        usage()

    #
    # Parse the global options.
    #
    try:
        opts, args = getopt.getopt(sys.argv[1:script], "", [ "verbose", "help", "capass="])
    except getopt.GetoptError:
        usage()

    verbose = False
    capass = None
    for o, a in opts:
       if o == "--verbose":
          verbose = True
       if o == "--help":
          usage()
       elif o == "--capass":
          capass = a

    try:
        if sys.argv[script] == "init":
           init(script, home, cafile, capass, verbose)
           sys.exit(0)

        factory = lambda: getCertificateAuthority(home, cafile, capass, verbose)
        if sys.argv[script] == "create":
           create(script, factory)
        elif sys.argv[script] == "export":
           export(script, factory)
        elif sys.argv[script] == "list":
           list(script, factory)
        elif sys.argv[script] == "show":
           show(script, factory)
        else:
           usage()
    except RuntimeError as err:
        print("Error: {0}".format(err))

    return 0

if __name__ == '__main__':
    sys.exit(main())
