#!/bin/bash
set -o errexit -o nounset
set -x

MAKEDIR="$(dirname "$0")"
# build env.sh only if needed
# it is handy if someone is executing run.sh in parallel
test ! -f "${MAKEDIR}/env.sh" && make depend -C "${MAKEDIR}"
source "${MAKEDIR}/env.sh"

# compatibility with old TESTS= env variable
# add --scenarios= only if the variable TESTS is non-empty
python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q --log-level=40 "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} "$@"
