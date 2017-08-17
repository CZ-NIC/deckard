FROM cznic/ubuntu:16.04
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# knot-resolver used for comparative tests
# we do not care that much about particular version of resolvers
# we want to install newer version of Augeas because those from Ubuntu repositories are incredibly slow on some operations
# context: https://www.redhat.com/archives/augeas-devel/2017-June/msg00000.html
RUN LC_ALL=C.UTF-8 add-apt-repository ppa:raphink/augeas -y
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y knot-resolver
RUN apt-get install -y unbound
RUN apt-get install -y pdns-recursor
RUN apt-get install -y python3-augeas python3-pep8 pylint3 python3-pip python3-jinja2 python3-yaml python3-pytest
# version of dnspython in Ubuntu repository is f**ked up
RUN pip3 install --upgrade dnspython selenium xvfbwrapper

