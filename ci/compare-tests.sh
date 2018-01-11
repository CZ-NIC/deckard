#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$0")/common.sh"
TESTRUNNER="$1"
: comparing results from test script "${TESTRUNNER}"

# Run specified test runner on HEAD and again on merge base for master..HEAD
# Fail if result of any test not modified between master..HEAD changed
# (i.e. any change in Deckard should not change results of non-modified tests)

function extract_test_results {
	# from log $1 extract test status lines like this:
	# [ FAIL ] sets/resolver/iter_badglue.rpl
	# [  OK  ] sets/resolver/iter_badraw.rpl
	# no spaces are allowed in test names
	grep -o '^\[[^]]*\] [^ ]*\.rpl' "$1" | sort --field-separator=']' --key=2 | uniq
}

function find_modified_tests {
	: detect tests affected by current merge request
	: store list of modified tests in ${MODIFIED_TESTS_FILE}
	git diff --numstat "${MERGEBASE}..${HEAD}" | cut -f 3 | fgrep .rpl > "${MODIFIED_TESTS_FILE}" || : no modified tests detected
}

function filter_test_results {
	: skip tests which are listed in ${MODIFIED_TESTS_FILE}
	grep --fixed-strings --invert-match --file="${MODIFIED_TESTS_FILE}"
}


MODIFIED_TESTS_FILE="/tmp/modified_tests"
find_modified_tests
LOGS[0]="${MODIFIED_TESTS_FILE}"

: get test results from version under test
"${TESTRUNNER}" -n $(nproc) --junit-xml=/tmp/head.xml

: get test results from common ancestor with master branch
git checkout --force --detach "${MERGEBASE}"
git clean -xdf
"${TESTRUNNER}" -n $(nproc) --junit-xml=/tmp/base.xml
test -z "$(./junit_compare.py /tmp/head.xml /tmp/base.xml /tmp/modified_tests)" && echo "OK, no differences found"