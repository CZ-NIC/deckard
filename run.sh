#!/bin/bash
set -o errexit -o nounset
MAKEDIR="$(dirname "$0")"
faketime -m --exclude-monotonic "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} --boxed -s "$@"

faketime -m "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} --boxed -s --mtime "$@"
