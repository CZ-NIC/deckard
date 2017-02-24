#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$(readlink -f "$0")")/common.sh"

PYFILES=$(find . \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-name '*.py' -print -o \
	-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print)

: check if version under test does not produce critical errors
${PYTHON} -m pylint -E ${PYFILES}

: no critical errors, compare score between versions
rm -rf ~/.pylint.d
: get test results from common ancestor with master branch
git checkout --force --detach "${MERGEBASE}"
git clean -xdf
# set of Python files might have changed during checkout
PYFILES=$(find . \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-name '*.py' -print -o \
	-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print)
${PYTHON} -m pylint ${PYFILES} &> /tmp/base.log || : old version is not clear
LOGS[0]="/tmp/base.log"
echo ==================== merge base ====================
cat /tmp/base.log
echo ==================== merge base end ====================

: get test results from version under test
git checkout --force --detach "${HEAD}"
git clean -xdf
${PYTHON} -m pylint ${PYFILES} &> /tmp/head.log || : version under test is not clear
LOGS[1]="/tmp/head.log"
echo ==================== candidate version ====================
cat /tmp/head.log
echo ==================== candidate end ====================

: check if candidate version produced more messages than the base
grep '^|\(convention\|refactor\|warning\|error\).*+' /tmp/head.log \
	&& { \
		echo "New pylint message detected: Use diff base.log head.log and go fix it!"; \
		exit 1; \
	} \
	|| echo "OK, no new pylint messages detected"
