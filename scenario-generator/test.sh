#!/usr/bin/env bash
BROWSER=$1
RESOLVER=$2
PAGE=$3
DATE=$4
DIR="$(pwd)"
DATADIR="$DIR/data/"
LOGDIR="$DIR/logs/"
FILE=$DATADIR$RESOLVER'-'$BROWSER'-'$PAGE'-'$DATE".pcap"
LOG=$LOGDIR$RESOLVER'-'$BROWSER'-'$PAGE'-'$DATE".log"
RESLOG=$LOGDIR"RESOLVER-"$RESOLVER'-'$PAGE'-'$DATE".log"
# SETUP DNS RESOLVER
if [ "$RESOLVER" = "bind" ]; then
	cp $DIR/resolv.conf /etc
	cp $DIR/named.conf.options /etc/bind
	sudo service bind9 restart &> /dev/null
	if [ $? != 0 ]; then
		echo "Failed to start resolver" > $LOG
		exit 1
	fi
fi
# SETUP BROWSER DRIVER
PATH=$PATH:$DIR
sudo tcpdump -i any -w $FILE &> /dev/null &
sleep 1

if [ "$BROWSER" = "firefox" ]; then
	./firefox.py $PAGE &> $LOG
	STATUS=$?
else
	echo "Invalid or unsuported browser" > $LOG
	exit 1
fi

sleep 2

PID=$(ps -e | pgrep tcpdump)
if [ -z $PID ]; then
	exit $STATUS
fi

kill -2 $PID

while ( ps -p $PID &> /dev/null )
do
	sleep 0.5
done

exit $STATUS
