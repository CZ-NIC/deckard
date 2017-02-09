#!/bin/bash

# Path to scenario files
TESTS=sets/resolver

# Path to daemon
DAEMON=kresd
     
# Template file name
TEMPLATE=template/kresd.j2

# Config file name
CONFIG=config

export TESTS DAEMON TEMPLATE CONFIG

echo '=== Testing WITHOUT query minimization ==='
export NO_MINIMIZE="true"
make
echo '=== Testing WITH query minimization ==='
export NO_MINIMIZE="false"
make
