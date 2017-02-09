#!/bin/bash
set -o nounset

# Path to scenario files
TESTS=${TESTS:-"sets/resolver"}

# Path to daemon
DAEMON=${DAEMON:-"kresd"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/kresd.j2"}

# Config file name
CONFIG=${CONFIG:-"config"}

export TESTS DAEMON TEMPLATE CONFIG

MAKEDIR="$(dirname "$(readlink -f "$0")")"
echo '=== Testing WITHOUT query minimization ==='
export NO_MINIMIZE="true"
make -C "${MAKEDIR}"
echo '=== Testing WITH query minimization ==='
export NO_MINIMIZE="false"
make -C "${MAKEDIR}"
