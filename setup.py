#!/usr/bin/env python2
import sys
from distutils.core import setup

version = '0.1.2'

kwargs = {
    'name' : 'pydnstest',
    'version' : version,
    'description' : 'DNS toolkit',
    'long_description' : \
    """pydnstest is a DNS software testing library. It supports parsing and running Unbound-like test scenarios,
       and setting up a mock DNS server. It's based on dnspython.""",
    'author' : 'Marek Vavrusa',
    'author_email' : 'marek@vavrusa.com',
    'license' : 'BSD',
    'url' : 'https://github.com/CZ-NIC/deckard',
    'packages' : ['pydnstest'],
    'classifiers' : [
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Software Development :: Libraries :: Python Modules",
        ],
    }

if sys.hexversion >= 0x02050000:
    kwargs['requires'] = ['dns']
    kwargs['provides'] = ['pydnstest']

setup(**kwargs)
