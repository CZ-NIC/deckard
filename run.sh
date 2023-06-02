#!/bin/bash
MAKEDIR="$(dirname "$0")"

# Currently there no tests requiring faking monotonic time in this repository (there are some elsewhere)
# but at the same time, none of them break when faking monotonic time.
# And python 3.11 causes issues with --exclude-monotonic
# https://github.com/wolfcw/libfaketime/issues/426
faketime -m "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} --forked "$@"
exit $?
