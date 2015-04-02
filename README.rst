The Ice Certificate Utilities package is a small Python library to
easily create certificates to use with Ice clients or servers.

Here's an example on how to create a certificate:

::
  import IceCertUtils

  factory = IceCertUtils.CertificateFactory()

  # Create the certificate with the alias "server"
  cert = factory.create("server", ip="127.0.0.1", dns="test.foo.org")

  # Save the certificate in the PKCS12 format
  cert.save("server.p12")
