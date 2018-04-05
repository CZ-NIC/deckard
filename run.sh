MAKEDIR="$(dirname "$0")"

LDPRELOAD=$(make depend -C "${MAKEDIR}")

source ${MAKEDIR}/env.sh

# compatibility with old TESTS= env variable
# add --scenarios= only if the variable TESTS is non-empty
python3 -m pytest -q tests/test_runner.py ${TESTS:+"--scenarios=${TESTS}"} "$@"

RETVAL=$?

if [[ $RETVAL -eq 4 && "$@" =~ .*-n.* ]]
then
    echo "Running on multiple cores failed. Is pytest-xdist module installed?"
fi

exit $RETVAL
