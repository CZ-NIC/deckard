#!/bin/bash -x
#set -o errexit -o nounset

REALPATH=$(command -v realpath)

ADDITIONAL="-f 1"

if [ -n "${REALPATH}" ]; then
    DECKARD_ROOT="$(dirname "$(realpath "${0}")")/"
else
    DECKARD_ROOT="$(dirname "${0}")"
fi

if [ -n "${1}" ]; then
    BUILD_ROOT="${1}/"
    ADDITIONAL="${ADDITIONAL} -m \"${BUILD_ROOT}\""
else
    BUILD_ROOT=""
fi

if [ -n "${2}" ]; then
    SOURCE_ROOT="${2}/"
else
    SOURCE_ROOT=""
fi

export ADDITIONAL

echo "Deckard root: ${DECKARD_ROOT}"
echo "Source root:  ${SOURCE_ROOT}"
echo "Build root:   ${BUILD_ROOT}"
echo "Additional:   ${ADDITIONAL}"

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
