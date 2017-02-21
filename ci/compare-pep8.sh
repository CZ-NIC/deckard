#!/bin/bash
set -o nounset -o xtrace -o errexit
source "$(dirname "$(readlink -f "$0")")/common.sh"

git diff "${MERGEBASE}..${HEAD}" | pep8 --diff --show-source --max-line-length=100 && echo "OK, no PEP8 errors detected"
