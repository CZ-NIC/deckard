FROM cznic/ubuntu:16.04
MAINTAINER Knot DNS <knot-dns@labs.nic.cz>

WORKDIR /root
CMD ["/bin/bash"]

# knot-resolver used for comparative tests
# we do not care that much about particular version
RUN apt-get update
RUN apt-get upgrade -y
RUN apt-get install -y knot-resolver
RUN apt-get install -y python-pep8  pylint  python-dnspython  python-jinja2
RUN apt-get install -y python3-pep8 pylint3 python3-dnspython python3-jinja2
