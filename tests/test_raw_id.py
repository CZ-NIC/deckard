#!/usr/bin/python3
import ipaddress
import sys

import dns.message

from pydnstest import mock_client

q = dns.message.make_query("anything", "A")
qid = q.id.to_bytes(2, "big", signed=False)
sock = mock_client.setup_socket("1.2.3.4", 53)
mock_client.send_query(sock, q)

if mock_client.get_answer(sock) == qid:
    sys.exit(0)
else:
    sys.exit(1)
