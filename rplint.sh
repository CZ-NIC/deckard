#!/bin/bash
set -x
set -o errexit -o nounset
MAKEDIR="$(dirname "$0")"
python3 -m pytest -c "${MAKEDIR}/rplint_pytest.ini" ${TESTS:+"--scenarios=${TESTS}"} "$@"
