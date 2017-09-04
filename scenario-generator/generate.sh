# Deckard test generator
#!/usr/bin/env bash
PROG="Deckard test generator"
VER="version 0.1"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SCENARIO="$DIR/scenarios"
LOGDIR="$DIR/logs"
TMP="$DIR/tmp"
CAPSUBDIR="/capture"
CAPDATADIR="$DIR$CAPSUBDIR/data"
CAPLOGDIR="$DIR$CAPSUBDIR/logs"
CAPTURELOG="$LOGDIR/capture.log"
BUILDLOG="$LOGDIR/build.log"
PADDING=80
FLAGS=""
DATE=`date +%Y-%m-%d_%H-%M-%S`
RESOLVERS="unbound kresd bind"
BROWSERS="firefox chrome chrome-android chrome-ios"
IMAGES="firefox chrome"
# FUNCTIONS
# padding $1 - string, $2 - size
function padding {
	head -c $((($2-${#1})/8)) < /dev/zero | tr '\0' '\t'
	if [ $((($2-${#1})%8)) != 0 ]; then
		echo -e -n "\t"
	fi
}
function run_capture {
	ALL=0
	FAILED=0
	for BROWSER in $BROWSERS
	do
		IMAGE=$(echo $BROWSER | awk -F- '{print $1}')
		for RESOLVER in $RESOLVERS
		do
			for PAGE in $*;
			do
				ID=$(docker run -v "$DIR$CAPSUBDIR:$CAPSUBDIR" -w $CAPSUBDIR -it deckard/$IMAGE:local)
				docker exec -it $ID $CAPSUBDIR/test.sh $BROWSER $RESOLVER $PAGE $DATE
				STATUS=$?
				docker stop $ID &>/dev/null
				docker rm $ID &>/dev/null
				ALL=$(($ALL+1))
				if [ ! $STATUS == 0 ]; then
					echo -e "[FAIL]\t[$BROWSER]\t[$RESOLVER]\t[$PAGE]"
					FAILED=$(($FAILED+1))
				else
					echo -e "[OK]\t[$BROWSER]\t[$RESOLVER]\t[$PAGE]"
				fi;
			done
		done
	done
	echo "$FAILED out of $ALL failed"

	if [ $ALL -eq $FAILED ]; then
		exit 1
	else
		exit 0
	fi
}
# ARGUMENTS
while [[ $# -gt 0 ]]
do
case "$1" in
	-v|--version)
		echo "$PROG version $VER"
		exit 0
 	;;
	-c|--clean)
		rm -rf -- $LOGDIR $CAPLOGDIR $CAPDATADIR
		FLAGS="$FLAGS -c"
 	;;
	-h|--help)
 		echo "$PROG version $VER"
		echo "Program arguments (input required)"
		echo "	-v | --version"
		echo "	-h | --help"
		echo "	-c | --clean					clean data and log folder"
		echo "	-f | --file <filename>				input from file"
		echo "	-d | --domain <domain | list of domains>	input from command line"
		exit 0
	;;
	-f|--file)
		if [[ $# -gt 1 ]]; then
			FILE=$(cat $2)
			STATUS=$?
			if [ $STATUS -ne 0 ]; then
				echo Invalid input file
				exit $STATUS
			fi
		fi
	shift
	;;
	-d|--domain)
		while [[ $# -gt 1 ]]
		do
			if [[ $2 != -* ]]; then
				FILE="$FILE $2"
				shift
			else
				break
			fi
		done
	;;
	*)
		echo "$PROG version $VER"
		echo "Invalid argument. See help (-h/--help)"
		exit 1
	;;
esac
shift
done
if [ -z "$FILE" ]; then
	if [[ $FLAGS == *"-c"* ]]; then
		exit 0
	fi
	echo "$PROG version $VER"
	echo "No input specified. See help (-h/--help)"
	exit 1
fi
# PREPARE
mkdir -p $LOGDIR $SCENARIO "$DIR$CAPSUBDIR" $CAPDATADIR $CAPLOGDIR
# BUILDING DOCKER IMAGES
for IMAGE in $IMAGES
do
	echo -e "[START] Building $IMAGE docker image"
	docker build -t deckard/$IMAGE:local $DIR/dockerfiles/$IMAGE > $BUILDLOG
	STATUS=$?
	if [ $STATUS -ne 0 ]; then
		echo Failed to build $IMAGE docker image. See $BUILDLOG
		exit $STATUS
	else
		echo -e "[FINISH] Building $IMAGE docker image"
	fi
done
# RUN CAPTURE
run_capture $FILE | tee  $CAPTURELOG
STATUS=$?
if [ $STATUS -ne 0 ]; then
	exit $STATUS
fi

# CONTINUE WITH PROCESSING
mkdir -p $TMP
for DOMAIN in $FILE
do
	grep "\[$DOMAIN\]" "$CAPTURELOG" | grep "\[OK\]" &> /dev/null # TODO - Processing different browsers
	if [ $? -eq 0 ]; then
		# TODO - remove browser specific lookups + if only browser specific => error + maybe on browser capture level
		#PROCESS PCAP AND GENERATE TEST
		# TMP - Use kresd and firefox as source of browser-resolver comunication
		'''tcpdump -r $CAPDATADIR/kresd-firefox-$DOMAIN-$DATE.pcap "port 53 and host 127.0.0.1" -w $TMP/$DOMAIN-base-filtered.pcap
		FILES="$TMP/$DOMAIN-base-filtered.pcap"
		for BROW in $BROWSERS
		do
			for RES in $RESOLVERS
			do
				tcpdump -r $CAPDATADIR/$RES-$BROW-$DOMAIN-$DATE.pcap "port 53 and not host 127.0.0.1" -w $TMP/$RES-$BROW-$DOMAIN-filtered.pcap
				FILES="$FILES $TMP/$RES-$BROW-$DOMAIN-filtered.pcap"
			done
		done
		# remove duplicate packets
		mergecap -F pcap -w $TMP/$DOMAIN-final.pcap $FILES'''
		SCFILE="$SCENARIO/$DOMAIN-$DATE.rpl"
		$DIR/sg-scenario.py $CAPDATADIR/kresd-firefox-$DOMAIN-$DATE.pcap  $DOMAIN-$DATE > $SCFILE
		if [ $? -ne 0 ]; then
			echo "[Scenario generation] Error occured"
		else
			echo "[Scenario generation] Scenario written into: $SCFILE"
		fi
	else
		echo "[Resolver capture][$DOMAIN] Skipping failed domain"
	fi
done
rm -r $TMP
