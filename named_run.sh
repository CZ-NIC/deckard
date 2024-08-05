#!/usr/bin/env bash
set -o errexit -o nounset
named -V | grep --quiet -- '--without-jemalloc' || echo 'WARNING: Make sure BIND is compiled without jemalloc library; for 9.17+ use ./configure --without-jemalloc'
MINOR="$(named -v | cut -d . -f 2)"
if [[ "$MINOR" -le "13" ]]
then
	echo 'WARNING: For BIND <= 9.13.2 manually remove qname-minimization option from named.conf template referenced in configs/named.yaml (usually template/named.j2)'
fi

RUNDIR="$(dirname "$0")"
cd "$RUNDIR" && ./run.sh --config configs/named.yaml "$@"
