The Ice Certificate Utilities package includes the iceca command line utility and a small Python library to allow creating certificates for Ice clients or servers.

It relies on PyOpenSSL for the creation of certificates. The Java KeyStore files are created with the keytool utility. The Java BouncyCastle provider is required to create BouncyCastle KeyStore files.

Installation
============

We recommend using ``pip`` or ``easy_install`` to install this package.

Package Contents
================

The iceca command line utility
------------------------------

The iceca utility provides a small certificate authority to allow creating certificates for use with Ice client and servers. It supports commands for initialization of the CA database, certification creation and export.

Usage:
::

    usage: iceca [--verbose --help --capass <pass>] init create list show export

    The iceca command manages a small certificate authority to create and sign
    certificates for Ice clients or servers.

    Commands:
    init     Initialize the certificate authority database
    create   Create and sign a certificate/key pair
    list     List the created certificates
    show     Show a given certificate
    export   Export a given certificate

Usage of the ``init`` subcommand:

::

    usage: init [--overwrite --no-capass]

    Initializes the certificate authority database.

    Options:
    --overwrite    Overwrite the existing CA database
    --no-capass    Don't protect the CA with a password

Usage of the ``create`` subcommand:

::

    usage: create [--ip=<ip>] [--dns=<dns>] <alias> [<common-name>]

    Creates and signs a certificate. A certificate is identified by its alias. If no
    common name is specified, the alias is used as the common name.

    Options:
    --ip    Optional IP subject alternative name field
    --dns   Optional DNS subject alternative name field

Usage of the ``list`` subcommand:

::

    usage: list

    List aliases for the certificates created with this CA.

Usage of the ``show`` subcommand:

::

    usage: show <alias>

    Print out the certificate associated to the given alias.

Usage of the ``export`` subcommand:

::

    usage: export [--password <password>] [--alias <alias>] path

    Export a certificate from the CA to the given file path. If --alias isn't
    specified, the filename indicates which certificate to export. The file
    extension also specifies the export format for the certificate. Supported
    formats are:

     PKCS12 (.p12, .pfx)
     PEM (.pem)
     DER (.der, .cer, .crt)
     JKS (.jks, requires keytool to be in the PATH)
     BKS (.bks, requires keytool and support for the BouncyCastle provider)

    Options:
    --password  The password to use for protecting the exported certificate
    --alias     The alias of the certificate to export

The IceCertUtils module
-----------------------

Here's an example on how to create a server and client certificate with the IceCertUtils module:

::

    import IceCertUtils

    #
    # Create the certicate factory
    #
    factory = IceCertUtils.CertificateFactory(cn = "My CA")

    # Get the CA certificate and save it to PEM/DER and JKS files
    factory.getCA().save("cacert.pem").save("cacert.der").save("cacert.jks")

    #
    # Create a client certificate
    #
    client = factory.create("client", cn = "Client")

    # Save the client certificate to the PKCS12 format
    client.save("client.p12")

    # Save the client certificate to the JKS format and also include the CA
     certificate in the keystore with the alias "cacert"
    client.save("client.jks", caalias="cacert")

    #
    # Create the server certificate, include IP and DNS subject alternative names.
    #
    server = factory.create("server", cn = "Server", ip="127.0.0.1", dns="server.foo.com")

    # Save the server certificate to the PKCS12 format
    server.save("server.p12")

    # Save the server certificate to the JKS format
    server.save("server.jks", caalias="cacert")

    # Save the client and server certificates to the BKS format. If the BKS
    # provider is not installed this will throw.
    try:
        client.save("client.bks", caalias="cacert")
        server.save("server.bks", caalias="cacert")
    except Exception as ex:
        print("warning: couldn't generate BKS certificates:\n" + str(ex))

    factory.destroy()
