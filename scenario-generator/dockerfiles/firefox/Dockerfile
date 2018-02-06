FROM selenium/standalone-firefox
USER root

RUN apt-get update && apt-get install -y unbound \
bind9 \
bind9utils \
bind9-doc \
knot-resolver \
python3 \
python3-pip \
tcpdump \
sudo \
xvfb \
tcpdump \
dnsutils \
sudo \
software-properties-common

RUN LC_ALL=C.UTF-8 add-apt-repository ppa:cz.nic-labs/knot-dns
RUN LC_ALL=C.UTF-8 add-apt-repository ppa:cz.nic-labs/knot-resolver

RUN apt-get update && apt-get install -y \
knot-resolver

# workaround for apparmor bug
RUN mv /usr/sbin/tcpdump /usr/bin/tcpdump

RUN pip3 install selenium xvfbwrapper
