#
# Copyright (c) ZeroC, Inc. All rights reserved.
#

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import sys

hasOpenSSL=False
try:
    import OpenSSL
    hasOpenSSL=True
except:
    pass

with open('README.rst') as file:
    long_description = file.read()

setup(
  name = 'zeroc-icecertutils',
  packages = ['IceCertUtils'],
  version = '1.0.5',
  description = 'ZeroC Ice certificate utilities',
  long_description = long_description,
  author = 'ZeroC, Inc.',
  author_email = 'info@zeroc.com',
  url = 'https://github.com/zeroc-ice/icecertutils',
  download_url = 'https://github.com/zeroc-ice/icecertutils/archive/v1.0.5.tar.gz',
  keywords = ['ice', 'certificate', 'ca', 'ssl'],
  install_requires = (["pyopenssl>=22", "cryptography>=41"] if not hasOpenSSL or sys.platform == "win32" else []),
  license='BSD',
  entry_points = {
      'console_scripts' : ["iceca=IceCertUtils.IceCaUtil:main"],
  },
  classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 3'
        'Programming Language :: Python :: 3.11',
  ],
  test_suite = "tests.factory",
)
