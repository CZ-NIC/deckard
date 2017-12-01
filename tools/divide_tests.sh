#!/bin/bash

# Sorts .rpl tests into several categories.
# Takes a diretory with the tests as an argument and moves the test to its subdirectories.

source=$1


# Test with the same name is already imported in deckard/sets/resolver
echo Already imported:
mkdir -p $source/imported
for test in `comm -12 <(ls -F ../sets/resolver/*.rpl | xargs -n 1 basename) <(ls -F $source/*.rpl | xargs -n 1 basename)`
do
    echo -e '\t' $test
    mv $source/$test $source/imported
done

# Parse failed
echo Parse failed:
mkdir -p $source/parsefail
for test in $source/*.rpl
do
    if ! python3 parse.py $test >/dev/null 2>/dev/null
    then
        echo -e '\t' $test
        mv $test $source/parsefail
    fi
done


# Invalid DSA signatures (common in old testbound tests)
echo Invalid DSA signatures:
mkdir -p $source/invaliddsa
for test in $source/*.rpl
do
    if ! python3 invalid_dsa.py $test >/dev/null 2>/dev/null
    then 
        echo -e '\t' $test
        mv $test $source/invaliddsa
    fi
done


# Working on kresd in deckard
echo Working:
mkdir -p $source/working

for test in $source/*.rpl
do
    path=$(readlink -m $test)
    if TESTS=$path ./../kresd_run.sh >/dev/null 2>/dev/null
    then 
        echo -e '\t' $test
        mv $test $source/working
    fi
done


# Others
echo Others:
mkdir -p $source/others
for test in $source/*.rpl
do
    echo -e '\t' $test
    mv $test $source/others
done