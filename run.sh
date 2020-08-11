#!/bin/bash
set -o errexit -o nounset
MAKEDIR="$(dirname "$0")"
faketime -m --exclude-monotonic "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "not monotonic" --boxed "$@"
faketime -m "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "monotonic" --boxed "$@"
echo "exit code: $?"
exit $(( $? == 5 ? 0 : $? ))  # Currently there are no tests requiring faking monotonic time in this repository (there might be some in future)
# pytest returns code 5 on "no tests where run" so we just ignore it
