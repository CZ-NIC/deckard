#!/bin/bash
set -o nounset -o errexit
CIDIR="$(dirname "$(readlink -f "$0")")"
ORIGNAME="$(git symbolic-ref -q --short HEAD || git describe --all --always HEAD)"
FAILURE_DETECTED="?"

function checkout_back {
	git checkout --force "${ORIGNAME}" || (echo "Warning: unable to checkout back!" && exit 5)

	test "${FAILURE_DETECTED}" "==" "0" && echo "All tests passed, good work!"
	test "${FAILURE_DETECTED}" "!=" "0" && echo "Problem found, go fix it!"
}

STATUS=$(git status --untracked-files=normal --porcelain)
test -n "${STATUS}" && echo "Working tree is dirty, commit your changes now." && exit 2

# return back to whatever branch we were on the beginning
# to avoid need for git checkout before fixing reported bugs
trap checkout_back EXIT
trap "{ FAILURE_DETECTED=1; }" ERR

for PYTHON in python2 python3
do
	export PYTHON

	"${CIDIR}"/compare-pylint.sh
	checkout_back
	git clean -xdf

	"${CIDIR}"/compare-pep8.sh
	checkout_back
	git clean -xdf

	"${CIDIR}"/compare-tests.sh "${CIDIR}/../kresd_run.sh"
	checkout_back
	git clean -xdf
done

# at this point all the tests passed so we can clean up
git clean -xdf
FAILURE_DETECTED=0
trap - ERR
