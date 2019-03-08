#!/bin/bash
make depend
source env.sh
export SOCKET_WRAPPER_DIR=/tmp
python3 -m pydnstest.testserver --scenario $(pwd)/tests/deckard_raw_id.rpl &
python3 -m tools.test_raw_id