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
cp $DIR/resolv.conf /etc
if [ "$RESOLVER" = "bind" ]; then
	cp $DIR/named.conf.options /etc/bind
	sudo service bind9 restart &> /dev/null
elif [ "$RESOLVER" = "kresd" ]; then
        kresd -a 127.0.0.1 -v -c $DIR/kresd.conf -f 1 /tmp > $RESLOG &
elif [ "$RESOLVER" = "unbound" ]; then
	unbound -c $DIR/unbound.conf > $RESLOG &
fi

if [ $? != 0 ]; then
	echo "Failed to start resolver" >> $RESLOG
	exit 1
fi
# SETUP BROWSER DRIVER
sudo tcpdump -i any -w $FILE port 53 &> /dev/null &
sleep 1

if [ "$BROWSER" = "firefox" ]; then
	./firefox.py $PAGE &> $LOG
elif [ "$BROWSER" = "chrome" ]; then
	./chrome.py $PAGE &> $LOG
elif [ "$BROWSER" = "chrome-android" ]; then
	./chrome-android.py  $PAGE &> $LOG
elif [ "$BROWSER" = "chrome-ios" ]; then
	./chrome-ios.py  $PAGE &> $LOG
else
	echo "Invalid or unsuported browser" > $LOG
	exit 1
fi

PID=$(ps -e | pgrep tcpdump)
kill -2 $PID

while ( ps -p $PID &> /dev/null )
do
	sleep 0.5
done

exit 0
