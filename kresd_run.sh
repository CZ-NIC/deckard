#!/bin/bash
set -o errexit -o nounset

RUNDIR="$(dirname "$0")"
cd "$RUNDIR" && ./run.sh --config configs/kresd.yaml "$@"
