# **********************************************************************
#
# Copyright (c) 2015-2015 ZeroC, Inc. All rights reserved.
#
# **********************************************************************

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
import sys

setup(
  name = 'zeroc-ice-certutils',
  packages = ['IceCertUtils'],
  version = '1.0b',
  description = 'ZeroC Ice Certificate Utilities',
  author = 'ZeroC, Inc.',
  author_email = 'info@zeroc.com',
  url = 'https://github.com/zeroc-inc/ice-certutils',
  download_url = 'https://github.com/zeroc-inc/ice-certutils/tarball/1.0b',
  keywords = ['ice', 'certificate', 'ca', 'ssl'],
  install_requires = (["pyopenssl>=0.14"] if sys.platform == "win32" else []),
  classifiers = [
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Security',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
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
