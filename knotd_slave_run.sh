#!/bin/bash

# Path to scenario files
TESTS=sets/knotd/slave

# Path to daemon
DAEMON=knotd
     
# Template file name
TEMPLATE=template/knotd_slave.j2 

# Config file name
CONFIG=knotd.conf

# Additional parameter for knotd
# it means configuration file can be found in working directory
ADDITIONAL="-c ./knotd.conf"

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

echo 'INFO: Tests require Knot compiled with ./configure --enable-recvmmsg=no'
make
