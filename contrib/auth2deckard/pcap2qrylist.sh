#!/bin/bash
# parse pcap specified as $1 and print list of DNS query names and types:
# Example output:
# . 48
# Cz. 2
# cz. 48

set -o errexit -o nounset
tshark -r "$1" -Y dns -T fields -e dns.qry.name -e dns.qry.type | sed -e 's#\t#. #' -e 's#^<Root>##' | sort -u --ignore-case
