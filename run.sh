#!/bin/bash
set -o errexit -o nounset

MAKEDIR="$(dirname "$0")"
rm -f "${MAKEDIR}/env.sh"
LDPRELOAD="$(make depend -C "${MAKEDIR}")"
source "${MAKEDIR}/env.sh"

# compatibility with old TESTS= env variable
# add --scenarios= only if the variable TESTS is non-empty
python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} "$@"
