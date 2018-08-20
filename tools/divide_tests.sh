#!/bin/bash

# Sorts .rpl tests into several categories.
# Takes a diretory with the tests as an argument and moves the test to its subdirectories.
# Env variable SCRIPT= sets *_run.sh script for finding working tests, default script is kresd_run.sh

set -o nounset
set -o errexit

SOURCE="$1"

SCRIPT=${SCRIPT:-"./../kresd_run.sh"}

# Test with the same name is already imported in deckard/sets/resolver
echo Already imported:
mkdir -p "$SOURCE/imported"
for TEST in `comm -12 <(ls -F ../sets/resolver/*.rpl | xargs -n 1 basename) <(ls -F "$SOURCE"/*.rpl | xargs -n 1 basename)`
do
    echo -e '\t' "$TEST"
    mv "$SOURCE/$TEST" "$SOURCE/imported"
done

# Parse failed
echo Parse failed:
mkdir -p "$SOURCE/parsefail"
for TEST in "$SOURCE/"*.rpl
do
    if ! python3 parse.py "$TEST" >/dev/null 2>/dev/null
    then
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$SOURCE/parsefail"
    fi
done


# Invalid DSA signatures (common in old testbound tests)
echo Invalid DSA signatures:
mkdir -p "$SOURCE/invaliddsa"
for TEST in "$SOURCE/"*.rpl
do
    if ! python3 invalid_dsa.py "$TEST" >/dev/null 2>/dev/null
    then 
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$SOURCE/invaliddsa"
    fi
done


# Working in selected script 
echo Working in $SCRIPT:
mkdir -p "$SOURCE/working"
for TEST in "$SOURCE/"*.rpl
do
    if TESTS="$(readlink -m $TEST)" $SCRIPT >/dev/null 2>/dev/null
    then 
        echo -e '\t' $(basename "$TEST")
        mv "$TEST" "$SOURCE/working"
    fi
done

echo Others:
mkdir -p "$SOURCE/others"
for TEST in "$SOURCE/"*.rpl
do
    echo -e '\t' $(basename "$TEST")
    mv "$TEST" "$SOURCE/others"
done
