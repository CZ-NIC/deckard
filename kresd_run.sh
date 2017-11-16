#!/bin/bash
set -o errexit -o nounset

# Path to scenario files
TESTS=${TESTS:-"sets/resolver"}

# Path to daemon
DAEMON=${DAEMON:-"kresd"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/kresd.j2"}

# Config file name
CONFIG=${CONFIG:-"config"}

# Additional parameters for kresd - non-interactive mode
ADDITIONAL="-f 1"

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

MAKEDIR="$(dirname "$(readlink -f "$0")")"
echo '=== Testing WITH query minimization ==='
export QMIN="true"
make -C "${MAKEDIR}"
echo '=== Testing WITHOUT query minimization ==='
export QMIN="false"
make -C "${MAKEDIR}"
