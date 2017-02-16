#!/bin/bash

# Path to scenario files
TESTS=${TESTS:-"sets/resolver"}

# Path to daemon
DAEMON=${DAEMON:-"unbound"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/unbound.j2:template/hints_zone.j2:template/unbound_dnssec.j2"}

# Config file name
CONFIG=${CONFIG:-"unbound.conf:hints.zone:ta.keys"}

# Additional parameter for unbound
# it means configuration file can be found in working directory
ADDITIONAL=${ADDITIONAL:-"-d -c unbound.conf"}

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

MAKEDIR="$(dirname "$(readlink -f "$0")")"
echo '=== Testing WITHOUT query minimization ==='
export NO_MINIMIZE="true"
make -C "${MAKEDIR}"
echo '=== Testing WITH query minimization ==='
export NO_MINIMIZE="false"
make -C "${MAKEDIR}"
