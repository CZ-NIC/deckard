import ipaddress

import dns.message

import answer_checker

FORWARDER = ipaddress.IPv4Address("127.0.0.1")
ALL = {"opcode", "qtype", "qname", "flags", "rcode", "answer", "authority", "additional"}


SIMPLE_QUERY = dns.message.make_query("good-a.test.knot-resolver.cz", "A")
SIMPLE_ANSWER = dns.message.from_text("""id 12757
opcode QUERY
rcode NOERROR
flags QR RD RA
edns 0
payload 4096
;QUESTION
good-a.test.knot-resolver.cz. IN A
;ANSWER
good-a.test.knot-resolver.cz. 3600 IN A 217.31.192.130
;AUTHORITY
;ADDITIONAL
""")

def test_supports_udp_answers():
    return answer_checker.send_and_check(SIMPLE_QUERY, SIMPLE_ANSWER, FORWARDER, ALL)

def test_supports_tcp_answers():
    return answer_checker.send_and_check(SIMPLE_QUERY, SIMPLE_ANSWER, FORWARDER, ALL, tcp=True)

EDNS_QUERY = dns.message.make_query("good-a.test.knot-resolver.cz", "A", use_edns=0)
def test_supports_EDNS0():
    answer = answer_checker.get_answer(EDNS_QUERY, FORWARDER)
    if answer.edns != 0:
        raise ValueError("EDNS0 not supported")


DO_QUERY = dns.message.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
def test_supports_DO():
    answer = answer_checker.get_answer(DO_QUERY, FORWARDER)
    if not answer.flags & dns.flags.DO:
        raise ValueError("DO bit sent, but not recieved")


CD_QUERY = dns.message.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
CD_QUERY.flags += dns.flags.CD
def test_supports_CD():
    answer = answer_checker.get_answer(CD_QUERY, FORWARDER)
    if not answer.flags & dns.flags.DO:
        raise ValueError("CD bit sent, but not recieved")


RRSIG_QUERY = dns.message.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
RRSIG_ANSWER = dns.message.from_text("""id 10674
opcode QUERY
rcode NOERROR
flags QR RD RA
edns 0
eflags DO
payload 4096
;QUESTION
good-a.test.knot-resolver.cz. IN A
;ANSWER
good-a.test.knot-resolver.cz. 3600 IN A 217.31.192.130
good-a.test.knot-resolver.cz. 3600 IN RRSIG A 13 4 3600 20370101093230 20190118080230 58 test.knot-resolver.cz. 0Kr6dt/wA3av/POqxrTT+VNvGV2S/DS/ SJB4DKDMVP8kgEHWVnPz+xkT0oe4esac +VDNFuy7IZ33bXXV/eQ/rg==
;AUTHORITY
;ADDITIONAL
""")
def test_returns_RRSIG():
    return answer_checker.send_and_check(RRSIG_QUERY, RRSIG_ANSWER, FORWARDER, {"answertypes"})


DNSKEY_QUERY = dns.message.make_query("test.knot-resolver.cz", "DNSKEY", want_dnssec=True)
DNSKEY_ANSWER = dns.message.from_text("""id 8816
opcode QUERY
rcode NOERROR
flags QR RD RA
edns 0
eflags DO
payload 4096
;QUESTION
test.knot-resolver.cz. IN DNSKEY
;ANSWER
test.knot-resolver.cz. 3600 IN DNSKEY 256 3 13 b5ZQUzN5iD9ercgxPeeEh9qI8UzazMa6 vo8GCART4iQNzAcsB6xPYVopHKcjyssH MUiDoQgrjVd6hOLWQqnCtg==
test.knot-resolver.cz. 3600 IN DNSKEY 257 3 13 xrbuMAmJy3GlxUF46tJgP64cmExKWQBg iRGeLhfub9x3DV69D+2m1zom+CyqHsYY VDIjYOueGzj/8XFucg1bDw==
test.knot-resolver.cz. 3600 IN RRSIG DNSKEY 13 3 3600 20370101093230 20190118080230 60526 test.knot-resolver.cz. xjyl77lNvJyl36iYphIOEHIBP4AWCtJT YYIY0IHKK89MsZwgi9kpoD/Cl8Iv0O20 eyrnMI5ivBs7W9CIAMRemQ==
;AUTHORITY
;ADDITIONAL
""")
def test_supports_DNSKEY():
    return answer_checker.send_and_check(DNSKEY_QUERY, DNSKEY_ANSWER, FORWARDER, {"answertypes"})


DS_QUERY = dns.message.make_query("cz", "DS", want_dnssec=True)
DS_ANSWER = dns.message.from_text("""id 27792
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 4096
;QUESTION
cz. IN DS
;ANSWER
cz. 81506 IN DS 20237 13 2 cff0f3ecdbc529c1f0031ba1840bfb835853b9209ed1e508fff48451d7b778e2
cz. 81506 IN RRSIG DS 8 1 86400 20190131050000 20190118040000 16749 . unZZj5veyqb3IhadDn0oPlNjZZTrRbSO Yv3FSRkKBJI223NXfgvj+yZYsZIrdnVa Za1RzX/zX8OHwy2JgQeTxXJOVfayzsum LvTH9FgXI+AjIifDNGhK1r8IP7yYKnD9 My4x1UC6rE6xtzqKmN+ocr0GOBv9FK9X i/BnjRyePn3P10J6w+1PrS5gABx1kRzJ v7bpg2vrYxkfrqAQ4p88Lt3zgorvWVp/ fy2ZTRxWQhwJHmHOyxuaL8l+ss/q3UEr c4ea/ugTxtFEIZ5a3JnJKm7J8DC+189r wmUYiQ8ch43mooCRoRRGl4k7RwVN4mKd WTxEujfWcx/hRJqsTqi/qw==
;AUTHORITY
;ADDITIONAL
""")
def test_supports_DS():
    return answer_checker.send_and_check(DS_QUERY, DS_ANSWER, FORWARDER, {"answertypes"})


NSEC_NEGATIVE_QUERY = dns.message.make_query("nonexistent.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC_NEGATIVE_ANSWER = dns.message.from_text("""id 36132
opcode QUERY
rcode NXDOMAIN
flags QR RD RA
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.test.knot-resolver.cz. IN A
;ANSWER
;AUTHORITY
test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111232 21600 3600 604800 86400
good-a.test.knot-resolver.cz. 86400 IN NSEC test.knot-resolver.cz. A RRSIG NSEC
test.knot-resolver.cz. 86400 IN NSEC _version.test.knot-resolver.cz. A SOA TXT RRSIG NSEC DNSKEY CDS CDNSKEY
test.knot-resolver.cz. 3600 IN RRSIG SOA 13 3 3600 20370101093230 20190118080230 58 test.knot-resolver.cz. 9gFwbCBiKnuIcWlzbqTlFZfbF4d5hxg8 2MxNVYZ/pTh9cfkh4jxj6EO1wKJhVKv6 WHGVFqPFdlGAxHuuXs9U/A==
good-a.test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 4 86400 20370101093230 20190118080230 58 test.knot-resolver.cz. Iy7nEk66+G+qrcPE9yQlHMQWNvSIIvzJ CIyYxhPfcskJib9ndtLhzYfiVyjmXarR rMKZay5w6OfRaojDZy6HOg==
test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 3 86400 20370101093230 20190118080230 58 test.knot-resolver.cz. tumtHbzoscGbMzck+RxH88ZpID6f8GGj 9dAfvmK9/HxUxdMTYaIw9Mz/wGtNVKg/ O1g+p7UNdiiJfF7In2psTA==
;ADDITIONAL"""
)
def test_negative_nsec_answers():
    return answer_checker.send_and_check(NSEC_NEGATIVE_QUERY,
                                         NSEC_NEGATIVE_ANSWER,
                                         FORWARDER,
                                         {"authority"})


NSEC3_NEGATIVE_QUERY = dns.message.make_query("nonexistent.nsec3.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC3_NEGATIVE_ANSWER = dns.message.from_text("""id 48118
opcode QUERY
rcode NXDOMAIN
flags QR RD RA
edns 0
eflags DO
payload 4096
;QUESTION
nonexistent.nsec3.test.knot-resolver.cz. IN A
;ANSWER
;AUTHORITY
nsec3.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111234 21600 3600 604800 86400
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 mn71vn3kbnse5hkqqs7kc062nf9jna3u A SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370101135758 20190118122758 52462 nsec3.test.knot-resolver.cz. 3yDvbj11LhyCZdFCZImPCwZuntJS9I/L HwR44n+MUXJ3FPU91L2RN/EjeZYbeCmw E6k7YT6OIpIHsVEXxdiYPw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101135758 20190118122758 52462 nsec3.test.knot-resolver.cz. wFv+DmjD721IOg1Iy/FkF5cShMmEqqKX WZej0sszcfHCQ3saNaeeoLAZWwDkDgmn IqUeAr3O5Y9x4vogv1pRWw==
;ADDITIONAL
"""
)
def test_negative_nsec3_answers():
    return answer_checker.send_and_check(NSEC3_NEGATIVE_QUERY,
                                         NSEC3_NEGATIVE_ANSWER,
                                         FORWARDER,
                                         {"authority"})


UNKNOWN_TYPE_QUERY = dns.message.make_query("weird-type.test.knot-resolver.cz", "TYPE20025")
UNKNOWN_TYPE_ANSWER = dns.message.from_text("""id 1885
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
weird-type.test.knot-resolver.cz. IN TYPE20025
;ANSWER
weird-type.test.knot-resolver.cz. 3600 IN TYPE20025 \# 4 deadbeef
;AUTHORITY
;ADDITIONAL
""")
