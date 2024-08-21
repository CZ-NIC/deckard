#!/usr/bin/env bash
MAKEDIR="$(dirname "$0")"

pytest_uncollected_ecode=5  # https://docs.pytest.org/en/stable/reference/exit-codes.html
ci_skip_ecode=77            # https://mesonbuild.com/Unit-tests.html#skipped-tests-and-hard-errors

# Currently there no tests requiring faking monotonic time in this repository (there are some elsewhere)
# pytest returns code 5 on "no tests were run" so we just ignore it
faketime -m "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "monotonic" --forked "$@"
MONO_RES=$?
faketime -m --exclude-monotonic "" python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} -m "not monotonic" --forked "$@"
NONMONO_RES=$?

if [ $MONO_RES -eq $pytest_uncollected_ecode -a $NONMONO_RES -eq $pytest_uncollected_ecode ]
then
    # everything seems to have been skipped
    exit $ci_skip_ecode
fi

if [ $NONMONO_RES -ne 0 -a $NONMONO_RES -ne $pytest_uncollected_ecode ]
then
    exit $NONMONO_RES
fi
if [ $MONO_RES -ne 0 -a $MONO_RES -ne $pytest_uncollected_ecode ]
then
    exit $MONO_RES
fi
