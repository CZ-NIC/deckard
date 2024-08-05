#!/usr/bin/env python3
from setuptools import setup

version = '3.0'

setup(
    name='deckard',
    version=version,
    description='DNS toolkit',
    long_description=(
        "Deckard is a DNS software testing based on library pydnstest."
        "It supports parsing and running Unbound-like test scenarios,"
        "and setting up a mock DNS server. It's based on dnspython."),
    author='CZ.NIC',
    author_email='knot-dns-users@lists.nic.cz',
    license='BSD',
    url='https://gitlab.nic.cz/knot/deckard',
    packages=['pydnstest'],
    python_requires='>=3.5',
    install_requires=[
        'dnspython>=1.15',
        'jinja2',
        'PyYAML',
        'python-augeas'
    ],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3 :: Only'
        'Operating System :: POSIX :: Linux',
        'Topic :: Internet :: Name Service (DNS)',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Software Development :: Quality Assurance',
        'Topic :: Software Development :: Testing',
    ]
)
