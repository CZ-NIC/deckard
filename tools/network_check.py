"""Test suite to determine conditions of current network in regards to DNS(SEC) traffic.
Invoke with `python3 -m pytest network_check.py`. """
# pylint: disable=C0301,C0111
# flake8: noqa
import ipaddress
import socket

import pytest
import dns.message

import answer_checker

ALL = {"opcode", "qtype", "qname", "flags", "rcode", "answer", "authority", "additional"}

VERSION_QUERY = dns.message.make_query("_version.test.knot-resolver.cz", "TXT")
# dnspython's `makequery` function sets RD bit in the messsages.
# This is undesirable for query to authoritative servers since they
# may or may not copy RD flag to the response.
answer_checker.unset_flag(VERSION_QUERY, dns.flags.RD)
VERSION_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
_version.test.knot-resolver.cz. IN TXT
;ANSWER
_version.test.knot-resolver.cz. 3600 IN TXT "1"
;AUTHORITY
;ADDITIONAL
""")

def test_zone_version(server):
    return answer_checker.send_and_check(VERSION_QUERY,
                                         VERSION_ANSWER,
                                         server,
                                         ALL - {"authority"},
                                         unset_flags=[dns.flags.AD])
# Since AD bit may or may not be set by authoritative server
# (see https://tools.ietf.org/html/rfc4035#section-3.1.6) we normalise the answers
# by unsetting the AD bit.

QUERY = answer_checker.make_random_case_query("test.knot-resolver.cz", "A", want_dnssec=True, payload=4096)
answer_checker.unset_flag(QUERY, dns.flags.RD)
ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR AA
edns 0
eflags DO
payload 4096
;QUESTION
test.knot-resolver.cz. IN A
;ANSWER
test.knot-resolver.cz. 3600 IN A 217.31.192.130
test.knot-resolver.cz. 3600 IN RRSIG A 13 3 3600 20370119135450 20190205122450 58 test.knot-resolver.cz. G9DTWRE8QKe0MKyHn+PZcgf+ggIR9Sk+ E9qtd8IlpEt3+y28qPp0lgDQojpQL9sv lqgC0g5e2ZIsZWg1T5ICNQ==
;AUTHORITY
;ADDITIONAL
""")


def test_remote_udp_53(server):
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         server,
                                         ALL - {"authority"},
                                         unset_flags=[dns.flags.AD])


def test_remote_tcp_53(server):
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         server,
                                         ALL - {"authority"},
                                         tcp=True,
                                         unset_flags=[dns.flags.AD])

@pytest.mark.parametrize("non_existent_server", [ipaddress.ip_address("192.0.2.1"), ipaddress.ip_address("2001:db::1")])
def test_nonexistent_addres(non_existent_server):
    try:
        answer_checker.get_answer(QUERY, non_existent_server, timeout=1)
    except socket.timeout:
        return True
    return False


LONG_QUERY = answer_checker.make_random_case_query("Ns103.X4058.x4090.Rs.DNS-oarc.nET", "A", use_edns=0, payload=4096, want_dnssec=True)
answer_checker.unset_flag(LONG_QUERY, dns.flags.RD)
LONG_ANSWER = dns.message.from_text(""";
id 6040
opcode QUERY
rcode NOERROR
flags QR AA
edns 0
payload 4096
;QUESTION
Ns103.X4058.x4090.Rs.DNS-oarc.nET. IN A
;ANSWER
Ns103.X4058.x4090.Rs.DNS-oarc.nET. 59 IN CNAME rst.x4066.x4090.Rs.DNS-oarc.nET.
;AUTHORITY
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns00.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns01.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns02.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns03.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns04.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns05.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns06.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns07.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns08.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns09.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns10.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns11.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns12.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns13.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns14.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns15.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns16.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns17.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns18.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns19.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns20.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns21.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns22.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns23.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns24.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns25.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns26.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns27.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns28.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns29.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns30.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns31.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns32.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns33.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns34.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns35.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns36.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns37.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns38.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns39.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns40.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns41.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns42.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns43.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns44.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns45.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns46.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns47.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns48.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns49.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns50.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns51.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns52.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns53.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns54.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns55.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns56.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns57.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns58.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns59.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns60.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns61.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns62.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns63.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns64.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns65.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns66.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns67.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns68.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns69.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns70.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns71.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns72.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns73.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns74.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns75.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns76.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns77.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns78.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns79.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns80.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns81.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns82.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns83.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns84.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns85.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns86.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns87.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns88.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns89.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns90.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns91.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns92.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns93.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns94.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns95.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns96.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns97.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns98.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns99.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns100.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns101.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns102.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns103.x4066.x4090.Rs.DNS-oarc.nET.
x4066.x4090.Rs.DNS-oarc.nET. 59 IN NS ns104.x4066.x4090.Rs.DNS-oarc.nET.
;ADDITIONAL
ns00.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns01.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns02.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns03.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns04.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns05.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns06.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns07.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns08.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns09.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns10.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns11.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns12.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns13.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns14.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns15.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns16.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns17.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns18.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns19.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns20.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns21.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns22.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns23.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns24.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns25.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns26.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns27.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns28.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns29.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns30.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns31.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns32.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns33.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns34.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns35.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns36.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns37.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns38.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns39.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns40.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns41.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns42.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns43.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns44.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns45.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns46.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns47.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns48.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns49.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns50.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns51.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns52.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns53.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns54.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns55.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns56.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns57.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns58.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns59.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns60.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns61.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns62.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns63.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns64.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns65.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns66.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns67.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns68.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns69.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns70.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns71.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns72.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns73.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns74.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns75.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns76.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns77.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns78.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns79.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns80.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns81.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns82.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns83.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns84.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns85.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns86.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns87.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns88.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns89.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns90.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns91.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns92.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns93.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns94.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns95.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns96.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns97.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns98.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns99.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns100.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns101.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns102.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns103.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
ns104.x4066.x4090.Rs.DNS-oarc.nET. 59 IN A 64.191.0.135
""")


def test_udp_fragmentation():
    return answer_checker.send_and_check(LONG_QUERY,
                                         LONG_ANSWER,
                                         ipaddress.ip_address("64.191.0.134"),
                                         ALL - {"authority"},
                                         unset_flags=[dns.flags.AD])


QUERY_WITH_SMALL_PAYLOAD = answer_checker.make_random_case_query("test.knot-resolver.cz", "TXT", use_edns=0, payload=1280, want_dnssec=True)
answer_checker.unset_flag(QUERY_WITH_SMALL_PAYLOAD, dns.flags.RD)
TRUNCATED_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR AA TC
edns 0
payload 4096
;QUESTION
test.knot-resolver.cz. IN TXT
;ANSWER
;AUTHORITY
;ADDITIONAL
""")


def test_udp_fragmentation_truncated(server):
    return answer_checker.send_and_check(QUERY_WITH_SMALL_PAYLOAD,
                                         TRUNCATED_ANSWER,
                                         server,
                                         ALL - {"authority"},
                                         unset_flags=[dns.flags.AD])
