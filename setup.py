# **********************************************************************
#
# Copyright (c) 2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import sys

setup(
  name = 'zeroc-icecertutils',
  packages = ['IceCertUtils'],
  version = '1.0.0',
  description = 'ZeroC Ice certificate utilities',
  author = 'ZeroC, Inc.',
  author_email = 'info@zeroc.com',
  url = 'https://github.com/zeroc-ice/icecertutils',
  download_url = 'https://github.com/zeroc-ice/icecertutils/archive/v1.0.0.tar.gz',
  keywords = ['ice', 'certificate', 'ca', 'ssl'],
  install_requires = (["pyopenssl>=0.14"] if sys.platform == "win32" else []),
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

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
  ],
  test_suite = "tests.factory",
)
