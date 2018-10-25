#!/usr/bin/env bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$0")/common.sh"

PYFILES=$(find . \
	-path ./.git -prune -o \
	-path ./contrib -o \
	-type d -exec test -e '{}/__init__.py' \; -print -prune -o \
	-name '*.py' -print -o \
	-type f -exec grep -qsm1 '^#!.*\bpython' '{}' \; -print)
set -e

${PYTHON} -m mypy --ignore-missing-imports ${PYFILES}
