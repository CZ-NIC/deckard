#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$0")/common.sh"

git diff "${MERGEBASE}..${HEAD}" | ${PYTHON} -m pep8 --ignore=W503 --diff --show-source --max-line-length=100 && echo "OK, no PEP8 errors detected"
