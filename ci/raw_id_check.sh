#!/bin/bash
make depend
cat env.sh
source env.sh
export SOCKET_WRAPPER_DIR=/tmp
python3 -m pydnstest.testserver --scenario $(pwd)/tests/deckard_raw_id.rpl &
sleep 1
python3 -m ci.raw_id