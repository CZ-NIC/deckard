#!/usr/bin/env python
import sys
from distutils.core import setup

version = '0.1.2'

kwargs = {
    'name': 'pydnstest',
    'version': version,
    'description': 'DNS toolkit',
    'long_description':
    """pydnstest is a DNS software testing library.
       It supports parsing and running Unbound-like test scenarios,
       and setting up a mock DNS server. It's based on dnspython.""",
    'author': 'Marek Vavrusa',
    'author_email': 'marek@vavrusa.com',
    'license': 'BSD',
    'url': 'https://github.com/CZ-NIC/deckard',
    'packages': ['pydnstest'],
    'install_requires': [
        'dnspython>=1.15',
        'jinja2',
        'PyYAML',
        'python-augeas',
        'selenium',
        'xvfbwrapper'
    ],
    'classifiers': [
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
}

setup(**kwargs)
