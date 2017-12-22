#!/bin/bash
set -o errexit -o nounset

# Path to scenario files
TESTS=${TESTS:-"sets/resolver"}

# Path to daemon
DAEMON=${DAEMON:-"unbound"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/unbound.j2:template/hints_zone.j2"}

# Config file name
CONFIG=${CONFIG:-"unbound.conf:hints.zone"}

# Additional parameter for unbound
# it means configuration file can be found in working directory
ADDITIONAL=${ADDITIONAL:-"-d -c unbound.conf"}

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

MAKEDIR="$(dirname "$0")"
make -C "${MAKEDIR}"
