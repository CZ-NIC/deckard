#!/bin/bash

# Path to scenario files
TESTS=${TESTS:-"sets/resolver"}

# Path to daemon
DAEMON=${DAEMON:-"pdns_recursor"}

# Template file name
TEMPLATE=${TEMPLATE:-"template/recursor.j2:template/hints_zone.j2:template/pdns_dnssec.j2"}

# Config file name
CONFIG=${CONFIG:-"recursor.conf:hints.pdns:dnssec.lua"}

# Additional parameter for pdns_recursor
# it means configuration file can be found in working directory
ADDITIONAL=${ADDITIONAL:-"--config-dir=./"}

# SIGTERM leads to return code -15 instead of clean 0 so we have to ignore it
IGNORE_EXIT_CODE=1

export TESTS DAEMON TEMPLATE CONFIG ADDITIONAL IGNORE_EXIT_CODE

MAKEDIR="$(dirname "$(readlink -f "$0")")"
make -C "${MAKEDIR}"
