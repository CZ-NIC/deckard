from ipaddress import IPv4Address, IPv6Address
from typing import Optional, Union, Set

import dns.message

import pydnstest.matchpart
import pydnstest.mock_client

def send_and_check(question: Union[dns.message.Message, bytes],
                   expected: dns.message.Message,
                   server: Union[IPv4Address, IPv6Address],
                   match_fields: Set[str],
                   port: int = 53,
                   tcp: bool = False,
                   source: Optional[Union[IPv4Address, IPv6Address]] = None) -> bool:
    """Checks if DNS answer recieved for a question from a server matches expected one in specified
    field. See pydnstest.matchpart for more information on match fields

    Returns True on success, raises an exceptions on failure.
    """

    sock = pydnstest.mock_client.setup_socket(str(server), port, source=source, tcp=tcp)
    pydnstest.mock_client.send_query(sock, question)
    answer = pydnstest.mock_client.get_dns_message(sock)

    for field in match_fields:
        pydnstest.matchpart.match_part(expected, answer, field)

    return True

# Queries can be dns.message.Message…
query_message = dns.message.make_query("test.knot-resolver.cz", "DS", want_dnssec=True)

# …or a bytes object in a byte format (same query as the one above)
query_raw = b'\xb8F\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x04test\rknot-resolver\x02cz\x00\x00+\x00\x01\x00\x00)\x05\x00\x00\x00\x80\x00\x00\x00'

# Expected answer has to be a dns.message.Message (otherwise matching would not work).
expected_answer = dns.message.from_text("""id 26843
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 512
;QUESTION
test.knot-resolver.cz. IN DS
;ANSWER
test.knot-resolver.cz. 1799 IN DS 29017 8 2 482653368ca59cd628d26e169fdf0eb8278a438264d1f50da85324d30676869f
test.knot-resolver.cz. 1799 IN RRSIG DS 13 3 1800 20181227073000 20181213060000 44033 knot-resolver.cz. 3uM+sFMYC1yrndNMER74As/vgaQmkNke 6jtBECM+UHs35Ti+qzFTlY8D5EZ+fENh ko5tgAyuqBL7fzDknUC9SQ==
;AUTHORITY
;ADDITIONAL
""")

answer_with_changed_RRSIG = dns.message.from_text("""id 26843
opcode QUERY
rcode NOERROR
flags QR RD RA AD
edns 0
eflags DO
payload 512
;QUESTION
test.knot-resolver.cz. IN DS
;ANSWER
test.knot-resolver.cz. 1799 IN DS 29017 8 2 482653368ca59cd628d26e169fdf0eb8278a438264d1f50da85324d30676869f
test.knot-resolver.cz. 1799 IN RRSIG DS 13 3 1800 20181227073000 20181213060000 44033 knot-resolver.cz. 4uM+sFMYC1yrndNMER74As/vgaQmkNke 6jtBECM+UHs35Ti+qzFTlY8D5EZ+fENh ko5tgAyuqBL7fzDknUC9SQ==
;AUTHORITY
;ADDITIONAL
""")

# Server is specified simply by its IP Adress
resolver_4 = IPv4Address("1.1.1.1")
resolver_6 = IPv6Address("2606:4700:4700::1111")


# Match fields should be some subset of pydnstest.matchpart.MATCH.keys()
fields = {"opcode", "qname", "qtype", "answer"}

# Returns True
print(send_and_check(query_message, expected_answer, resolver_4, fields))

# Throws an exception
print(send_and_check(query_raw, answer_with_changed_RRSIG, resolver_6, fields))
