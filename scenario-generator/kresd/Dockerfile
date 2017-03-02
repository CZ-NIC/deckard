FROM cznic/ubuntu:16.04

RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y knot-resolver \
python3 \
python3-pip \
tcpdump \
sudo \
firefox \
xvfb \
tcpdump \
dnsutils \
sudo

RUN pip3 install selenium xvfbwrapper
