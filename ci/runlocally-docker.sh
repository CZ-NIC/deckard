#!/bin/bash
''' A script for running Deckard tests in docker locally. '''
IMAGE="registry.labs.nic.cz/knot/knot-resolver/ci:debian-stable"
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

ID=$(docker run -d -v "$DECKARD:$DECKARD" $MOUNT -it $IMAGE)
docker exec -it $ID bash -c "cd $DECKARD && make depend && $*"
docker stop $ID &>/dev/null
docker rm $ID &>/dev/null
