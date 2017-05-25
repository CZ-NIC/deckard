#!/bin/bash -x
#set -o errexit -o nounset

DECKARD_ROOT="$(dirname "$(readlink -f "${0}")")/"

if [ -n "${1}" ]; then
    BUILD_ROOT="${1}/"
else
    BUILD_ROOT=""
fi

if [ -n "${2}" ]; then
    SOURCE_ROOT="${2}/"
else
    SOURCE_ROOT=""
fi

echo "Deckard root: ${DECKARD_ROOT}"
echo "Source root:  ${SOURCE_ROOT}"
echo "Build root:   ${BUILD_ROOT}"

export TESTS="${TESTS:-sets/resolver}"
export DAEMON="${DAEMON:-${BUILD_ROOT}kresd}"
export TEMPLATE="${TEMPLATE:-template/kresd.j2}"
export CONFIG="${CONFIG:-config}"

echo '=== Testing WITH query minimization ==='
export QMIN="true"
make -C "${DECKARD_ROOT}"
echo '=== Testing WITHOUT query minimization ==='
export QMIN="false"
make -C "${DECKARD_ROOT}"
