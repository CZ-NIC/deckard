#!/bin/bash

# Path to scenario files
TESTS=sets/resolver

# Path to daemon
DAEMON=pdns_recursor
     
# Template file name
TEMPLATE=template/recursor.j2 

# Config file name
CONFIG=recursor.conf

# Additional parameter for pdns_recursor
# it means configuration file can be found in working directory
ADDITIONAL=--config-dir=./

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

make

