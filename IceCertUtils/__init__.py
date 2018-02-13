# **********************************************************************
#
# Copyright (c) 2015-2018 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

from IceCertUtils.PyOpenSSLCertificateUtils import PyOpenSSLCertificateFactory
from IceCertUtils.OpenSSLCertificateUtils import OpenSSLCertificateFactory
from IceCertUtils.KeyToolCertificateUtils import KeyToolCertificateFactory
from IceCertUtils.CertificateUtils import DistinguishedName, Certificate, defaultDN

CertificateFactory = CertificateUtils.getDefaultImplementation()
