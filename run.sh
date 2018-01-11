MAKEDIR="$(dirname "$0")"

LDPRELOAD=$(make depend -C "${MAKEDIR}")

source ${MAKEDIR}/env.sh

py.test -q tests/test_runner.py "$@"

RETVAL=$?

if [[ $RETVAL -eq 4 && "$@" =~ .*-n.* ]]
then
    echo "Running on multiple cores failed. Is pytest-xdist module installed?"
fi

exit $RETVAL