#!/bin/bash
MAKEDIR="$(dirname "$0")"

# Currently there no tests requiring faking monotonic time in this repository (there are some elsewhere)
# pytest returns code 5 on "no tests were run" so we just ignore it
faketime -m --exclude-monotonic "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "not monotonic" --boxed "$@"
NONMONO_RES=$(( $? == 5 ? 0 : $? ))
faketime -m "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "monotonic" --boxed "$@"
MONO_RES=$(( $? == 5 ? 0 : $? ))

if [ $NONMONO_RES -ne 0 ]
then
    exit $NONMONO_RES
fi
if [ $MONO_RES -ne 0 ]
then
    exit $MONO_RES
fi

