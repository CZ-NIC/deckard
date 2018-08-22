#!/bin/bash

# Sorts .rpl tests into several categories.
# Takes a diretory with the tests as an argument and moves the test to its subdirectories.
# Env variable SCRIPT= sets *_run.sh script for finding working tests, default script is kresd_run.sh
# Env variable DEST= sets output directory where the tests will be copied and divided into subfolders. Default value is working directory.

set -o nounset
set -o errexit

SOURCE="$1"

SCRIPT=${SCRIPT:-"./../kresd_run.sh"}
DEST=${DEST:-"."}

rm -rf "$DEST/sorted_tests"
mkdir "$DEST/sorted_tests"
for TEST in "$SOURCE/"*.rpl
do
    cp "$TEST" "$DEST/sorted_tests"
done

# Test with the same name is already imported in deckard/sets/resolver
echo Already imported:
mkdir -p "$DEST/sorted_tests/imported"
for TEST in `comm -12 <(ls -F ../sets/resolver/*.rpl | xargs -n 1 basename) <(ls -F "$DEST/sorted_tests" | xargs -n 1 basename)`
do
    echo -e '\t' "$TEST"
    mv "$DEST/sorted_tests/$TEST" "$DEST/sorted_tests/imported"
done

# Parse failed
echo Parse failed:
mkdir -p "$DEST/sorted_tests/parsefail"
for TEST in "$DEST/sorted_tests/"*.rpl
do
    if ! python3 parse.py "$TEST" >/dev/null 2>/dev/null
    then
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$DEST/sorted_tests/parsefail"
    fi
done


# Invalid DSA signatures (common in old testbound tests)
echo Invalid DSA signatures:
mkdir -p "$DEST/sorted_tests/invaliddsa"
for TEST in "$DEST/sorted_tests/"*.rpl
do
    if ! python3 invalid_dsa.py "$TEST" >/dev/null 2>/dev/null
    then 
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$DEST/sorted_tests/invaliddsa"
    fi
done


# Working in selected script 
echo Working in $SCRIPT:
mkdir -p "$DEST/sorted_tests/working"
for TEST in "$DEST/sorted_tests/"*.rpl
do
    if TESTS="$(readlink -m $TEST)" $SCRIPT >/dev/null 2>/dev/null
    then 
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$DEST/sorted_tests/working"
    fi
done

echo Others:
mkdir -p "$DEST/sorted_tests/others"
for TEST in "$DEST/sorted_tests/"*.rpl
do
    echo -e '\t' $(basename "$TEST")
    mv "$TEST" "$DEST/sorted_tests/others"
done

