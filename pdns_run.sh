#!/bin/bash

# Path to scenario files
TESTS=sets/resolver

# Path to daemon
DAEMON=$HOME/src/PowerDNS/pdns/pdns/recursordist/pdns_recursor
     
# Template file name
TEMPLATE=template/recursor.j2:template/hints_pdns.j2:template/dnssec_pdns.j2

# Config file name
CONFIG=recursor.conf:hints.pdns:dnssec.lua

# Additional parameter for pdns_recursor
# it means configuration file can be found in working directory
ADDITIONAL=--config-dir=./

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

make

