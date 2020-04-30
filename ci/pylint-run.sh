#!/bin/bash
set -o nounset -o errexit
source "$(dirname "$0")/common.sh"

PYFILES=$(find . \
	-path ./.git -prune -o \
	-path ./contrib -o \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-name '*.py' -print -o \
	-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print)

PYTHONPATH=. ${PYTHON} -m pylint -j 0 --rcfile pylintrc ${PYFILES}
