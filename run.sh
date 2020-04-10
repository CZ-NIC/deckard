#!/bin/bash
set -o errexit -o nounset

MAKEDIR="$(dirname "$0")"
# build env.sh only if needed
# it is handy if someone is executing run.sh in parallel
test ! -f "${MAKEDIR}/env.sh" && make depend -C "${MAKEDIR}"
source "${MAKEDIR}/env.sh"

python3 -m pytest -c "${MAKEDIR}/deckard_pytest.ini" --tb=short -q ${VERBOSE:+"--log-level=DEBUG"} "${MAKEDIR}" ${DECKARDFLAGS:-} ${TESTS:+"--scenarios=${TESTS}"} --boxed "$@"
