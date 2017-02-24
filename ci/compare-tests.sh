#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$(readlink -f "$0")")/common.sh"
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

: get results from all tests, including the failing ones
export MAKEFLAGS="--output-sync=target --keep-going -j$(nproc)"

: get test results from version under test
PYTHON=${PYTHON} "${TESTRUNNER}" &> /tmp/head.log || :
LOGS[1]="/tmp/head.log"
extract_test_results /tmp/head.log | filter_test_results &> /tmp/head.tests || (: "no tests left, huh?" && cat /tmp/head.log)
LOGS[2]="/tmp/head.tests"

: get test results from common ancestor with master branch
git checkout --force --detach "${MERGEBASE}"
git clean -xdf
PYTHON=${PYTHON} "${TESTRUNNER}" &> /tmp/base.log || :
LOGS[3]="/tmp/base.log"
extract_test_results /tmp/base.log | filter_test_results &> /tmp/base.tests || (: "no tests left, huh?" && cat /tmp/base.log)
LOGS[4]="/tmp/base.tests"

: tests which were not modified should produce the same results
diff -U0 /tmp/base.tests /tmp/head.tests && echo "OK, no differences found"
