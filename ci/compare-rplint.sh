#!/usr/bin/env bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$(readlink -f "$0")")/common.sh"


function find_new_tests {
	: detect tests affected by current merge request
	: store list of modified tests in ${NEW_TESTS_FILE}
  git diff --name-only --diff-filter=AM ${MERGEBASE} ${HEAD} | fgrep .rpl > "${NEW_TESTS_FILE}" || : no new tests detected
}

NEW_TESTS_FILE="/tmp/new_tests"
find_new_tests

truncate -s0 /tmp/rplint_fails

: run rplint of all new tests
FAIL=0
cat /tmp/new_tests
for test in $(cat ${NEW_TESTS_FILE})
do
  ${PYTHON} -m rplint $test >> /tmp/rplint_fails || FAIL=1
done

: if even one of the test does not pass rplint, fail
if [ "$FAIL" -eq 1 ]
then
  cat /tmp/rplint_fails
  exit 1
fi
exit 0
