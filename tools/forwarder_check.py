"""Test suite to test forwarders
Invoke with `python3 -m pytest forwarder_check.py --forwarder [IP of forwarder]`"""
# pylint: disable=C0301,C0111,C0103
# flake8: noqa
import ipaddress

import dns.message
import pytest
from pytest_dependency import depends

import answer_checker

ALL = {"opcode", "qtype", "qname", "flags", "rcode", "answer", "authority", "additional"}
HEADER = {"opcode", "qtype", "qname", "flags", "rcode"}

VERSION_QUERY = dns.message.make_query("_version.test.knot-resolver.cz", "TXT")
VERSION_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RA RD
;QUESTION
_version.test.knot-resolver.cz. IN TXT
;ANSWER
_version.test.knot-resolver.cz. 3600 IN TXT "1"
;AUTHORITY
;ADDITIONAL
""")

def test_zone_version(forwarder):
    return answer_checker.send_and_check(VERSION_QUERY,
                                         VERSION_ANSWER,
                                         forwarder,
                                         ALL - {"additional", "authority"})

SIMPLE_QUERY = answer_checker.make_random_case_query("good-a.test.knot-resolver.cz", "A")
SIMPLE_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
good-a.test.knot-resolver.cz. IN A
;ANSWER
good-a.test.knot-resolver.cz. 3600 IN A 217.31.192.130
;AUTHORITY
;ADDITIONAL""")

def test_supports_simple_answers(forwarder, tcp):
    return answer_checker.send_and_check(SIMPLE_QUERY,
                                         SIMPLE_ANSWER,
                                         forwarder,
                                         ALL - {"additional", "authority"},
                                         tcp=tcp)

EDNS_QUERY = answer_checker.make_random_case_query("good-a.test.knot-resolver.cz", "A", use_edns=0)


def test_supports_EDNS0(forwarder, tcp):
    answer = answer_checker.get_answer(EDNS_QUERY, forwarder, tcp=tcp)
    if answer.edns != 0:
        raise ValueError("EDNS0 not supported")

DO_QUERY = answer_checker.make_random_case_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)


def test_supports_DO(forwarder, tcp):
    answer = answer_checker.get_answer(DO_QUERY, forwarder, tcp=tcp)
    if not answer.flags & dns.flags.DO:
        raise ValueError("DO bit sent, but not recieved")

CD_QUERY = answer_checker.make_random_case_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
CD_QUERY.flags += dns.flags.CD


def test_supports_CD(forwarder, tcp):
    answer = answer_checker.get_answer(CD_QUERY, forwarder, tcp=tcp)
    if not answer.flags & dns.flags.CD:
        raise ValueError("CD bit sent, but not recieved")

RRSIG_QUERY = answer_checker.make_random_case_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
RRSIG_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
good-a.test.knot-resolver.cz. IN A
;ANSWER
good-a.test.knot-resolver.cz. 3600 IN A 217.31.192.130
good-a.test.knot-resolver.cz. 3600 IN RRSIG A 13 4 3600 20370119135450 20190205122450 58 test.knot-resolver.cz. n7BfrYwvRztj8khwefZxnVUSBm6vvIWH 3HGTfswPSUKqNrg6yqMIxm0dpLVPSIna hPnTnP3CP6G4SEfvAGk33w==
;AUTHORITY
;ADDITIONAL""")


def test_returns_RRSIG(forwarder, tcp):
    return answer_checker.send_and_check(RRSIG_QUERY,
                                         RRSIG_ANSWER,
                                         forwarder,
                                         HEADER | {"answerrrsigs"},
                                         tcp=tcp)

DNSKEY_QUERY = answer_checker.make_random_case_query("test.knot-resolver.cz", "DNSKEY", want_dnssec=True)
DNSKEY_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
test.knot-resolver.cz. IN DNSKEY
;ANSWER
test.knot-resolver.cz. 3600 IN DNSKEY 256 3 13 b5ZQUzN5iD9ercgxPeeEh9qI8UzazMa6 vo8GCART4iQNzAcsB6xPYVopHKcjyssH MUiDoQgrjVd6hOLWQqnCtg==
test.knot-resolver.cz. 3600 IN DNSKEY 257 3 13 xrbuMAmJy3GlxUF46tJgP64cmExKWQBg iRGeLhfub9x3DV69D+2m1zom+CyqHsYY VDIjYOueGzj/8XFucg1bDw==
test.knot-resolver.cz. 3600 IN RRSIG DNSKEY 13 3 3600 20370119141532 20190205124532 60526 test.knot-resolver.cz. TCJGKcojvwe5cQYJaj+vMS5/lW2xLDVi cABjowFhQ3ttTIfjNINBK1sAJgybmdtd 5GcBlgXOPz+QWRFJUnRU2g==
;AUTHORITY
;ADDITIONAL""")


def test_supports_DNSKEY(forwarder, tcp):
    return answer_checker.send_and_check(DNSKEY_QUERY,
                                         DNSKEY_ANSWER,
                                         forwarder,
                                         ALL - {"additional", "authority"},
                                         tcp=tcp)

DS_QUERY = answer_checker.make_random_case_query("test.knot-resolver.cz", "DS", want_dnssec=True)
DS_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
test.knot-resolver.cz. IN DS
;ANSWER
test.knot-resolver.cz.	1800	IN	DS	0 8 2 0000000000000baff1ed10ca1beefc0111ded1cedeadadd011c0feecaca0b011
test.knot-resolver.cz.	1800	IN	DS	60526 13 2 9E526A3D1D1D3F78BD11ABDCE8DE5A6CF9212CD2575D28FC10EBC046 F001AEA8
test.knot-resolver.cz.	1800	IN	RRSIG	DS 13 3 1800 20190227092958 20190213075958 23292 knot-resolver.cz. 9yBl60FpEgGt5R5JAKWWK1n1AGLSoeQDsX3nfLz/gQtljhKgnKgkM10T MZKIPUUY9jczh89ChoqCYFr+4MzURw==
;AUTHORITY
;ADDITIONAL""")
# DS signature with tag 0 is left dangling in the zone to trigger a bug in building of
# chain of trust in older versions of Unbound

def test_supports_DS(forwarder, tcp):
    return answer_checker.send_and_check(DS_QUERY,
                                         DS_ANSWER,
                                         forwarder,
                                         HEADER | {"answerrrsigs"},
                                         tcp=tcp)

NSEC_NEGATIVE_QUERY = answer_checker.make_random_case_query("nonexistent.nsec.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC_NEGATIVE_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NXDOMAIN
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.nsec.test.knot-resolver.cz. IN A
;ANSWER
;AUTHORITY
nsec.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
nsec.test.knot-resolver.cz. 7200 IN NSEC unsigned.nsec.test.knot-resolver.cz. A NS SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. Nwpe3F7+fiCeGgyP+0WgyGYC5N8MY4Pc bipFKsHBxgkwkdEyV395VvYCbhz5YuJb SyXsv9tXOVN+XSb5Sac8uQ==
nsec.test.knot-resolver.cz. 7200 IN RRSIG NSEC 13 4 7200 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. ugmndbqwWjM5Zc/ZCEt/FeGSuw70sasu jylUhFljwdalhRNNlLNcQY9Tlr8A8Vnc YJCwI36LrwAp9m/W2ysZxQ==
;ADDITIONAL""")


def test_negative_nsec_answers(forwarder, tcp):
    return answer_checker.send_and_check(NSEC_NEGATIVE_QUERY,
                                         NSEC_NEGATIVE_ANSWER,
                                         forwarder,
                                         HEADER | {"authority"}, tcp=tcp)

NSEC3_NEGATIVE_QUERY = answer_checker.make_random_case_query("nonexistent.nsec3.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC3_NEGATIVE_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NXDOMAIN
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.nsec3.test.knot-resolver.cz. IN A
;ANSWER
;AUTHORITY
nsec3.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A NS SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 druje9e1goigmosgk4m6iv7gbktg143a CNAME RRSIG
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. 9Ne2jUhyILPa5r0lAUdqkHtbkggSiRbt yqRaH3ENGlYcIIA3Rib6U2js+wEQpYVs SdQPcuzwAkYGmsqroSnDIw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. r7DbpNp4KXvV2a4TDoV3whUPpI6mmjKA bk5TQZnA/z1AwFMtzJDQJ7b9RCv2C9Es CbwKEa+/bLNH4N2Ed8RVPQ==
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370119135450 20190205122450 52462 nsec3.test.knot-resolver.cz. NXEa3JxBpufEqBDEUNQhH2kQpPQbXYDX /b1soMKA4CwSaRVgiMkw41vevUZ/XtPj SFl0D6ov88QEDLG2RzYy9g==
;ADDITIONAL""")


def test_negative_nsec3_answers(forwarder, tcp):
    return answer_checker.send_and_check(NSEC3_NEGATIVE_QUERY,
                                         NSEC3_NEGATIVE_ANSWER,
                                         forwarder,
                                         HEADER | {"authority"}, tcp=tcp)

UNKNOWN_TYPE_QUERY = answer_checker.make_random_case_query("weird-type.test.knot-resolver.cz", "TYPE20025", want_dnssec=True)
UNKNOWN_TYPE_ANSWER = dns.message.from_text(r""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 512
;QUESTION
weird-type.test.knot-resolver.cz. IN TYPE20025
;ANSWER
weird-type.test.knot-resolver.cz. 3506 IN TYPE20025 \# 4 deadbeef
weird-type.test.knot-resolver.cz. 3506 IN RRSIG TYPE20025 13 4 3600 20370119135450 20190205122450 58 test.knot-resolver.cz. eHON73HpRyhIalC4xHwu/zWcZWuyVC3T fpBaOQU1MabzitXBUy4dKoAMVXhcpj62 Pqiz2FxMMg6nXRQJupQDAA==
;AUTHORITY
;ADDITIONAL
""")


def test_unknown_rrtype(forwarder, tcp):
    return answer_checker.send_and_check(UNKNOWN_TYPE_QUERY,
                                         UNKNOWN_TYPE_ANSWER,
                                         forwarder,
                                         ALL - {"additional", "authority"},
                                         tcp=tcp)

NONEXISTENT_DS_DELEGATION_NSEC_QUERY = answer_checker.make_random_case_query("unsigned.nsec.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DS_DELEGATION_NSEC_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
unsigned.nsec.test.knot-resolver.cz. IN DS
;ANSWER
;AUTHORITY
nsec.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
unsigned.nsec.test.knot-resolver.cz. 7200 IN NSEC *.wild.nsec.test.knot-resolver.cz. NS RRSIG NSEC
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. Nwpe3F7+fiCeGgyP+0WgyGYC5N8MY4Pc bipFKsHBxgkwkdEyV395VvYCbhz5YuJb SyXsv9tXOVN+XSb5Sac8uQ==
unsigned.nsec.test.knot-resolver.cz. 7200 IN RRSIG NSEC 13 5 7200 20370119135450 20190205122450 25023 nsec.test.knot-resolver.cz. SWIzKCXTRQMz1n7myOioFrfbTljjR4jG NVRV43NWKtXQ6ftIR68wSVZ+6xsATHeG GXYYJxqaoviY+mLrJdJa/g==
;ADDITIONAL""")


def test_delegation_from_nsec_to_unsigned_zone(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_DS_DELEGATION_NSEC_QUERY,
                                         NONEXISTENT_DS_DELEGATION_NSEC_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp)

NONEXISTENT_DS_DELEGATION_NSEC3_QUERY = answer_checker.make_random_case_query("unsigned.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DS_DELEGATION_NSEC3_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
unsigned.nsec3.test.knot-resolver.cz. IN DS
;ANSWER
;AUTHORITY
nsec3.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
gk65ucsupb4m139fn027ci6pl01fk5gs.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 mn71vn3kbnse5hkqqs7kc062nf9jna3u NS
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. 9Ne2jUhyILPa5r0lAUdqkHtbkggSiRbt yqRaH3ENGlYcIIA3Rib6U2js+wEQpYVs SdQPcuzwAkYGmsqroSnDIw==
gk65ucsupb4m139fn027ci6pl01fk5gs.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370119135450 20190205122450 52462 nsec3.test.knot-resolver.cz. WjWrhgoRmw8+xMuzcGLqPx76xEvPTQjN OaJOEXzK7409Jc7tVHgpolbNxsDdI0u+ h6s5Du78yx4z0QOCq2VEzg==
;ADDITIONAL""")


def test_delegation_from_nsec3_to_unsigned_zone(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_DS_DELEGATION_NSEC3_QUERY,
                                         NONEXISTENT_DS_DELEGATION_NSEC3_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp)

NONEXISTENT_DELEGATION_FROM_NSEC_QUERY = answer_checker.make_random_case_query("nonexistent.nsec.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DELEGATION_FROM_NSEC_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NXDOMAIN
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.nsec.test.knot-resolver.cz. IN DS
;ANSWER
;AUTHORITY
nsec.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
nsec.test.knot-resolver.cz. 7200 IN NSEC unsigned.nsec.test.knot-resolver.cz. A NS SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. Nwpe3F7+fiCeGgyP+0WgyGYC5N8MY4Pc bipFKsHBxgkwkdEyV395VvYCbhz5YuJb SyXsv9tXOVN+XSb5Sac8uQ==
nsec.test.knot-resolver.cz. 7200 IN RRSIG NSEC 13 4 7200 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. ugmndbqwWjM5Zc/ZCEt/FeGSuw70sasu jylUhFljwdalhRNNlLNcQY9Tlr8A8Vnc YJCwI36LrwAp9m/W2ysZxQ==
;ADDITIONAL""")


def test_nonexistent_delegation_from_nsec(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_DELEGATION_FROM_NSEC_QUERY,
                                         NONEXISTENT_DELEGATION_FROM_NSEC_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp,
                                         unset_flags=[dns.flags.AA])
# Some resolvers treat generated proof of non-existence as authoritative data
# and set AA flag in this kind of answer, we have to normalize this by unsetting
# it.

NONEXISTENT_DELEGATION_FROM_NSEC3_QUERY = answer_checker.make_random_case_query("nonexistent.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DELEGATION_FROM_NSEC3_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NXDOMAIN
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.nsec3.test.knot-resolver.cz. IN DS
;ANSWER
;AUTHORITY
nsec3.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A NS SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 druje9e1goigmosgk4m6iv7gbktg143a CNAME RRSIG
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. 9Ne2jUhyILPa5r0lAUdqkHtbkggSiRbt yqRaH3ENGlYcIIA3Rib6U2js+wEQpYVs SdQPcuzwAkYGmsqroSnDIw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. r7DbpNp4KXvV2a4TDoV3whUPpI6mmjKA bk5TQZnA/z1AwFMtzJDQJ7b9RCv2C9Es CbwKEa+/bLNH4N2Ed8RVPQ==
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370119135450 20190205122450 52462 nsec3.test.knot-resolver.cz. NXEa3JxBpufEqBDEUNQhH2kQpPQbXYDX /b1soMKA4CwSaRVgiMkw41vevUZ/XtPj SFl0D6ov88QEDLG2RzYy9g==
;ADDITIONAL""")


def test_nonexistent_delegation_from_nsec3(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_DELEGATION_FROM_NSEC3_QUERY,
                                         NONEXISTENT_DELEGATION_FROM_NSEC3_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp,
                                         unset_flags=[dns.flags.AA])


NONEXISTENT_TYPE_NSEC3_QUERY = answer_checker.make_random_case_query("nsec3.test.knot-resolver.cz", "TYPE65281", want_dnssec=True)
NONEXISTENT_TYPE_NSEC3_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nsec3.test.knot-resolver.cz. IN TYPE65281
;ANSWER
;AUTHORITY
nsec3.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A NS SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. 9Ne2jUhyILPa5r0lAUdqkHtbkggSiRbt yqRaH3ENGlYcIIA3Rib6U2js+wEQpYVs SdQPcuzwAkYGmsqroSnDIw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 7200 IN RRSIG NSEC3 13 5 7200 20370126162631 20190212145631 52462 nsec3.test.knot-resolver.cz. r7DbpNp4KXvV2a4TDoV3whUPpI6mmjKA bk5TQZnA/z1AwFMtzJDQJ7b9RCv2C9Es CbwKEa+/bLNH4N2Ed8RVPQ==
;ADDITIONAL""")


def test_nonexistent_type_nsec3(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_TYPE_NSEC3_QUERY,
                                         NONEXISTENT_TYPE_NSEC3_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp)

NONEXISTENT_TYPE_NSEC_QUERY = answer_checker.make_random_case_query("nsec.test.knot-resolver.cz", "TYPE65281", want_dnssec=True)
NONEXISTENT_TYPE_NSEC_ANSWER = dns.message.from_text(""";
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
nsec.test.knot-resolver.cz. IN TYPE65281
;ANSWER
;AUTHORITY
nsec.test.knot-resolver.cz. 3600 IN SOA knot-s-01.nic.cz. hostmaster.nic.cz. 2018042476 10800 3600 1209600 7200
nsec.test.knot-resolver.cz. 7200 IN NSEC unsigned.nsec.test.knot-resolver.cz. A NS SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. Nwpe3F7+fiCeGgyP+0WgyGYC5N8MY4Pc bipFKsHBxgkwkdEyV395VvYCbhz5YuJb SyXsv9tXOVN+XSb5Sac8uQ==
nsec.test.knot-resolver.cz. 7200 IN RRSIG NSEC 13 4 7200 20370126162631 20190212145631 25023 nsec.test.knot-resolver.cz. ugmndbqwWjM5Zc/ZCEt/FeGSuw70sasu jylUhFljwdalhRNNlLNcQY9Tlr8A8Vnc YJCwI36LrwAp9m/W2ysZxQ==
;ADDITIONAL""")


def test_nonexistent_type_nsec(forwarder, tcp):
    return answer_checker.send_and_check(NONEXISTENT_TYPE_NSEC_QUERY,
                                         NONEXISTENT_TYPE_NSEC_ANSWER,
                                         forwarder,
                                         ALL, tcp=tcp)
