#!/bin/bash
set -o errexit -o nounset

# Path to scenario files
TESTS=${TESTS:-"sets/knotd/slave"}

# Path to daemon
DAEMON=${DAEMON:-"knotd"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/knotd_slave.j2"}

# Config file name
CONFIG=${CONFIG:-"knotd.conf"}

# Additional parameter for knotd
# it means configuration file can be found in working directory
ADDITIONAL=${ADDITIONAL:-"-c ./knotd.conf"}

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL

echo 'INFO: Tests require Knot compiled with ./configure --enable-recvmmsg=no
MAKEDIR="$(dirname "$(readlink -f "$0")")"
make -C "${MAKEDIR}"
