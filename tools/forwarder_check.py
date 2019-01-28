import ipaddress

import dns.message
import pytest

import answer_checker
import network_check

FORWARDER = ipaddress.IPv4Address("127.0.0.1")
ALL = {"opcode", "qtype", "qname", "flags", "rcode", "answer", "authority", "additional"}


SIMPLE_QUERY = answer_checker.make_query("good-a.test.knot-resolver.cz", "A")
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

test_zone_version = network_check.test_zone_version

@pytest.mark.parametrize("tcp", [True, False])
def test_supports_simple_answers(tcp):
    return answer_checker.send_and_check(SIMPLE_QUERY, SIMPLE_ANSWER, FORWARDER, ALL, tcp=tcp)


EDNS_QUERY = answer_checker.make_query("good-a.test.knot-resolver.cz", "A", use_edns=0)
@pytest.mark.parametrize("tcp", [True, False])
def test_supports_EDNS0(tcp):
    answer = answer_checker.get_answer(EDNS_QUERY, FORWARDER, tcp=tcp)
    if answer.edns != 0:
        raise ValueError("EDNS0 not supported")


DO_QUERY = answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
@pytest.mark.parametrize("tcp", [True, False])
def test_supports_DO(tcp):
    answer = answer_checker.get_answer(DO_QUERY, FORWARDER, tcp=tcp)
    if not answer.flags & dns.flags.DO:
        raise ValueError("DO bit sent, but not recieved")


CD_QUERY = answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
CD_QUERY.flags += dns.flags.CD
@pytest.mark.parametrize("tcp", [True, False])
def test_supports_CD(tcp):
    answer = answer_checker.get_answer(CD_QUERY, FORWARDER, tcp=tcp)
    if not answer.flags & dns.flags.DO:
        raise ValueError("CD bit sent, but not recieved")


RRSIG_QUERY = answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True)
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
@pytest.mark.parametrize("tcp", [True, False])
def test_returns_RRSIG(tcp):
    return answer_checker.send_and_check(RRSIG_QUERY, RRSIG_ANSWER, FORWARDER, {"answertypes"}, tcp=tcp)


DNSKEY_QUERY = answer_checker.make_query("test.knot-resolver.cz", "DNSKEY", want_dnssec=True)
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
@pytest.mark.parametrize("tcp", [True, False])
def test_supports_DNSKEY(tcp):
    return answer_checker.send_and_check(DNSKEY_QUERY, DNSKEY_ANSWER, FORWARDER, {"answertypes"}, tcp=tcp)


DS_QUERY = answer_checker.make_query("cz", "DS", want_dnssec=True)
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
@pytest.mark.parametrize("tcp", [True, False])
def test_supports_DS(tcp):
    return answer_checker.send_and_check(DS_QUERY, DS_ANSWER, FORWARDER, {"answertypes"}, tcp=tcp)


NSEC_NEGATIVE_QUERY = answer_checker.make_query("nonexistent.nsec.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC_NEGATIVE_ANSWER = dns.message.from_text("""id 31284
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
nsec.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111240 21600 3600 604800 86400
nsec.test.knot-resolver.cz. 86400 IN NSEC unsigned.nsec.test.knot-resolver.cz. A SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. IDA6arVYLCd54OPJeGVPEeIxvzi9fdje sz3sHMV4dCsOy0UXIDq9z+amGNK9y2l+ 3o4SoxbruGWh1/JVnkmUtg==
nsec.test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 4 86400 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. nWIaYBfbCz3HAmZ0ePdjcaa0xIzvbRMb OkEmoARSw6JvfamEWAz2hUeLihg/jcmZ X+/9dbpf3L3apbllfv3QOw==
;ADDITIONAL"""
)
@pytest.mark.parametrize("tcp", [True, False])
def test_negative_nsec_answers(tcp):
    return answer_checker.send_and_check(NSEC_NEGATIVE_QUERY,
                                         NSEC_NEGATIVE_ANSWER,
                                         FORWARDER,
                                         {"authority"}, tcp=tcp)


NSEC3_NEGATIVE_QUERY = answer_checker.make_query("nonexistent.nsec3.test.knot-resolver.cz", "A", want_dnssec=True)
NSEC3_NEGATIVE_ANSWER = dns.message.from_text("""id 52781
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
nsec3.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111236 21600 3600 604800 86400
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 druje9e1goigmosgk4m6iv7gbktg143a CNAME RRSIG
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111111240 20190128094240 52462 nsec3.test.knot-resolver.cz. j9xYhEPpCURzd1rF4NnwL1/nipjup8fO z0Tg3POXaYQr/9ovMBz6Upnt1nvAJ8zM yukkWNwbhNQJBsHUxX/PWw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101143104 20190118130104 52462 nsec3.test.knot-resolver.cz. urWKiAuNdUocco7sN8G0a6QjGyxiTlH7 k8Z/5P/hq1i5GH4iIwWgRTtcWJ/3mtpM LWDB4z4Eg4BPnNzGV0Y0Ew==
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101143104 20190118130104 52462 nsec3.test.knot-resolver.cz. PZcI6R68gjwNQBQ5DXY+WstesMCSnXR7 eg5y5AtplrUIzE6VNGM6PXrvmwr8I2UO CDBjF2Cn/cr/bY5YSK5oaw==
;ADDITIONAL
"""
)
@pytest.mark.parametrize("tcp", [True, False])
def test_negative_nsec3_answers(tcp):
    return answer_checker.send_and_check(NSEC3_NEGATIVE_QUERY,
                                         NSEC3_NEGATIVE_ANSWER,
                                         FORWARDER,
                                         {"authority"}, tcp=tcp)


UNKNOWN_TYPE_QUERY = answer_checker.make_query("weird-type.test.knot-resolver.cz", "TYPE20025")
UNKNOWN_TYPE_ANSWER = dns.message.from_text(r"""id 1885
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
@pytest.mark.parametrize("tcp", [True, False])
def test_unknown_rrtypes(tcp):
    return answer_checker.send_and_check(UNKNOWN_TYPE_QUERY,
                                         UNKNOWN_TYPE_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_DS_DELEGATION_NSEC_QUERY = answer_checker.make_query("unsigned.nsec.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DS_DELEGATION_NSEC_ANSWER = dns.message.from_text("""id 47553
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
nsec.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111240 21600 3600 604800 86400
unsigned.nsec.test.knot-resolver.cz. 86400 IN NSEC *.wild.nsec.test.knot-resolver.cz. NS RRSIG NSEC
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. IDA6arVYLCd54OPJeGVPEeIxvzi9fdje sz3sHMV4dCsOy0UXIDq9z+amGNK9y2l+ 3o4SoxbruGWh1/JVnkmUtg==
unsigned.nsec.test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 5 86400 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. NSd7tozIhhmjVuh9xa9VglTXkFn35i6L PC+sq8sryt8jQb/kN83WctQ+daoAvxGj ogoPvSAf4SCKgxUlLsgPIg==
;ADDITIONAL
""")
@pytest.mark.parametrize("tcp", [True, False])
def test_delegation_from_nsec_to_unsigned_zone(tcp):
    return answer_checker.send_and_check(NONEXISTENT_DS_DELEGATION_NSEC_QUERY,
                                         NONEXISTENT_DS_DELEGATION_NSEC_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_DS_DELEGATION_NSEC3_QUERY = answer_checker.make_query("unsigned.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DS_DELEGATION_NSEC3_ANSWER = dns.message.from_text("""id 15009
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
nsec3.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111236 21600 3600 604800 86400
gk65ucsupb4m139fn027ci6pl01fk5gs.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 mn71vn3kbnse5hkqqs7kc062nf9jna3u NS
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111111240 20190128094240 52462 nsec3.test.knot-resolver.cz. j9xYhEPpCURzd1rF4NnwL1/nipjup8fO z0Tg3POXaYQr/9ovMBz6Upnt1nvAJ8zM yukkWNwbhNQJBsHUxX/PWw==
gk65ucsupb4m139fn027ci6pl01fk5gs.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370111111240 20190128094240 52462 nsec3.test.knot-resolver.cz. aLfrvzn8UjBdAE2YB72igoUe8XmN0gGs MW2cAjEVPwICZQIFlrhmy90HvKO08AfA jTflykbeis+/WRnisvVbjg==
;ADDITIONAL
""")
@pytest.mark.parametrize("tcp", [True, False])
def test_delegation_from_nsec3_to_unsigned_zone(tcp):
    return answer_checker.send_and_check(NONEXISTENT_DS_DELEGATION_NSEC3_QUERY,
                                         NONEXISTENT_DS_DELEGATION_NSEC3_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_DELEGATION_FROM_NSEC_QUERY = answer_checker.make_query("nonexistent.nsec.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DELEGATION_FROM_NSEC_ANSWER = dns.message.from_text("""id 39425
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
nsec.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111240 21600 3600 604800 86400
nsec.test.knot-resolver.cz. 86400 IN NSEC unsigned.nsec.test.knot-resolver.cz. A SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. IDA6arVYLCd54OPJeGVPEeIxvzi9fdje sz3sHMV4dCsOy0UXIDq9z+amGNK9y2l+ 3o4SoxbruGWh1/JVnkmUtg==
nsec.test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 4 86400 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. nWIaYBfbCz3HAmZ0ePdjcaa0xIzvbRMb OkEmoARSw6JvfamEWAz2hUeLihg/jcmZ X+/9dbpf3L3apbllfv3QOw==
;ADDITIONAL""")
@pytest.mark.parametrize("tcp", [True, False])
def test_nonexistent_delegation_from_nsec(tcp):
    return answer_checker.send_and_check(NONEXISTENT_DELEGATION_FROM_NSEC_QUERY,
                                         NONEXISTENT_DELEGATION_FROM_NSEC_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_DELEGATION_FROM_NSEC3_QUERY = answer_checker.make_query("nonexistent.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True)
NONEXISTENT_DELEGATION_FROM_NSEC3_ANSWER = dns.message.from_text("""id 13765
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
nsec3.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111236 21600 3600 604800 86400
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 druje9e1goigmosgk4m6iv7gbktg143a CNAME RRSIG
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111111240 20190128094240 52462 nsec3.test.knot-resolver.cz. j9xYhEPpCURzd1rF4NnwL1/nipjup8fO z0Tg3POXaYQr/9ovMBz6Upnt1nvAJ8zM yukkWNwbhNQJBsHUxX/PWw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101143104 20190118130104 52462 nsec3.test.knot-resolver.cz. urWKiAuNdUocco7sN8G0a6QjGyxiTlH7 k8Z/5P/hq1i5GH4iIwWgRTtcWJ/3mtpM LWDB4z4Eg4BPnNzGV0Y0Ew==
af4kdouqgq3k3j0boq2bqlf4hi14c8qa.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101143104 20190118130104 52462 nsec3.test.knot-resolver.cz. PZcI6R68gjwNQBQ5DXY+WstesMCSnXR7 eg5y5AtplrUIzE6VNGM6PXrvmwr8I2UO CDBjF2Cn/cr/bY5YSK5oaw==
;ADDITIONAL
""")
@pytest.mark.parametrize("tcp", [True, False])
def test_nonexistent_delegation_from_nsec3(tcp):
    return answer_checker.send_and_check(NONEXISTENT_DELEGATION_FROM_NSEC3_QUERY,
                                         NONEXISTENT_DELEGATION_FROM_NSEC3_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_TYPE_NSEC3_QUERY = answer_checker.make_query("nsec3.test.knot-resolver.cz", "TYPE65281", want_dnssec=True)
NONEXISTENT_TYPE_NSEC3_ANSWER = dns.message.from_text("""id 4887
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
nsec3.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111236 21600 3600 604800 86400
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN NSEC3 1 0 10 9b987e46196cd181 6j18444t948b3ij9dlakm317q132ccii A SOA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY
nsec3.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111111240 20190128094240 52462 nsec3.test.knot-resolver.cz. j9xYhEPpCURzd1rF4NnwL1/nipjup8fO z0Tg3POXaYQr/9ovMBz6Upnt1nvAJ8zM yukkWNwbhNQJBsHUxX/PWw==
mn71vn3kbnse5hkqqs7kc062nf9jna3u.nsec3.test.knot-resolver.cz. 86400 IN RRSIG NSEC3 13 5 86400 20370101143104 20190118130104 52462 nsec3.test.knot-resolver.cz. urWKiAuNdUocco7sN8G0a6QjGyxiTlH7 k8Z/5P/hq1i5GH4iIwWgRTtcWJ/3mtpM LWDB4z4Eg4BPnNzGV0Y0Ew==
;ADDITIONAL""")
@pytest.mark.parametrize("tcp", [True, False])
def test_nonexistent_type_nsec3(tcp):
    return answer_checker.send_and_check(NONEXISTENT_TYPE_NSEC3_QUERY,
                                         NONEXISTENT_TYPE_NSEC3_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)


NONEXISTENT_TYPE_NSEC_QUERY = answer_checker.make_query("nsec.test.knot-resolver.cz", "TYPE65281", want_dnssec=True)
NONEXISTENT_TYPE_NSEC_ANSWER = dns.message.from_text("""id 42016
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
nsec.test.knot-resolver.cz. 3600 IN SOA dns1.example.com. hostmaster.example.com. 2010111240 21600 3600 604800 86400
nsec.test.knot-resolver.cz. 86400 IN NSEC unsigned.nsec.test.knot-resolver.cz. A SOA RRSIG NSEC DNSKEY CDS CDNSKEY
nsec.test.knot-resolver.cz. 3600 IN RRSIG SOA 13 4 3600 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. IDA6arVYLCd54OPJeGVPEeIxvzi9fdje sz3sHMV4dCsOy0UXIDq9z+amGNK9y2l+ 3o4SoxbruGWh1/JVnkmUtg==
nsec.test.knot-resolver.cz. 86400 IN RRSIG NSEC 13 4 86400 20370111113325 20190128100325 25023 nsec.test.knot-resolver.cz. nWIaYBfbCz3HAmZ0ePdjcaa0xIzvbRMb OkEmoARSw6JvfamEWAz2hUeLihg/jcmZ X+/9dbpf3L3apbllfv3QOw==
;ADDITIONAL
""")
@pytest.mark.parametrize("tcp", [True, False])
def test_nonexistent_type_nsec(tcp):
    return answer_checker.send_and_check(NONEXISTENT_TYPE_NSEC_QUERY,
                                         NONEXISTENT_TYPE_NSEC_ANSWER,
                                         FORWARDER,
                                         ALL, tcp=tcp)
