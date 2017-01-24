#!/bin/bash
# parse pcap specified as $1 and print timestamp of the first packet
# Example output:
# 20170127161325

set -o errexit -o nounset
DATE=$(tshark -r /tmp/all.pcapng -t ud -c 1 -T fields -e frame.time_epoch)
date --date=@${DATE} "+%Y%m%d%H%M%S"
