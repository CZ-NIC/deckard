#!/bin/bash
''' A script for running Deckard tests in docker locally. '''
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DECKARD=$(dirname $DIR)
MOUNT=''

case "$1" in
	-h|--help)
 		echo "A script for running Deckard tests in docker locally."
		echo "Usage: runlocally-docker.sh <command>"
		echo "  command - <make | kresd_run.sh | ci/runlocally.sh | ...> with parameters"
		echo "  	- run command as if in main directory of your repository"
		exit 0
	;;
esac

for string in $* # Extract directory with tests
do
	if [[ $string == "TESTS="* ]]; then
		TESTDIR=${string#*=}
		MOUNT="-v $TESTDIR:$TESTDIR"
	fi
done

echo "Start building Docker image"
docker build -t deckard/ci:local $DIR
STATUS=$?
if [ $STATUS -ne 0 ]; then
	echo Failed to build docker image.
	exit $STATUS
else
	echo "Finished building Docker image"
fi

ID=$(docker run -d -v "$DECKARD:$DECKARD" $MOUNT -it deckard/ci:local)
docker exec -it $ID bash -c "cd $DECKARD && make depend && $*"
docker stop $ID &>/dev/null
docker rm $ID &>/dev/null
