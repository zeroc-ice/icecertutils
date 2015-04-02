# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

from PyOpenSSLCertificateUtils import PyOpenSSLCertificateFactory
from OpenSSLCertificateUtils import OpenSSLCertificateFactory
from KeyToolCertificateUtils import KeyToolCertificateFactory
from CertificateUtils import DistinguishedName, Certificate

CertificateFactory = CertificateUtils.getDefaultImplementation()
