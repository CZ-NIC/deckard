#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$(readlink -f "$0")")/common.sh"


function find_new_tests {
	: detect tests affected by current merge request
	: store list of modified tests in ${NEW_TESTS_FILE}
  git diff --name-only --diff-filter=A ${MERGEBASE} ${HEAD} | fgrep .rpl > "${NEW_TESTS_FILE}" || : no new tests detected
}

NEW_TESTS_FILE="/tmp/new_tests"
find_new_tests

truncate -s0 /tmp/rplint_fails
for test in $(cat ${NEW_TESTS_FILE})
do
  ${PYTHON} -m rplint $test >> /tmp/rplint_fails
done

cat /tmp/rplint_fails
test "!" -s /tmp/rplint_fails
