#!/usr/bin/python3
import ipaddress
import sys

import dns.message

sys.path.append("tools")

import answer_checker

q = dns.message.make_query("anything", "A")

answer_checker.send_and_check(q, q, ipaddress.ip_address("127.0.0.127"), {"id"})
