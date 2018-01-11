#!/bin/bash
set -o errexit -o nounset
echo 'INFO: Tests require Knot compiled with ./configure --enable-recvmmsg=no'
RUNDIR="$(dirname "$0")"
cd $RUNDIR && ./run.sh --config configs/knotd_master.yaml "$@"


