"""Functions for easily send DNS queries and check recieved answers"""
# pylint: disable=C0301
# flake8: noqa

from ipaddress import IPv4Address, IPv6Address
import random
from typing import Union, Set

import dns.message

import pydnstest.matchpart
import pydnstest.mock_client


def unset_AD_bit(message: dns.message.Message) -> dns.message.Message:
    """Since AD bit may or may not be set by authoritative server
    (see https://tools.ietf.org/html/rfc4035#section-3.1.6) we normalise the answers
    by unsetting the AD bit."""
    message.flags &= ~dns.flags.AD
    return message


def send_and_check(question: Union[dns.message.Message, bytes],  # pylint: disable=R0913
                   expected: dns.message.Message,
                   server: Union[IPv4Address, IPv6Address],
                   match_fields: Set[str],
                   port: int = 53,
                   tcp: bool = False,
                   unset_AD: bool = False) -> bool:
    """Checks if DNS answer recieved for a question from a server matches expected one in specified
    field. See pydnstest.matchpart for more information on match fields

    Returns True on success, raises an exceptions on failure.
    """
    print("Sending query:\n%s\n" % question)
    answer = get_answer(question, server, port, tcp)

    if unset_AD:
        answer = unset_AD_bit(answer)

    print("Got answer:\n%s\n" % answer)
    print("Matching:\n%s\n%s\n" % (match_fields, expected))
    for field in match_fields:
        pydnstest.matchpart.match_part(expected, answer, field)

    return True


def get_answer(question: Union[dns.message.Message, bytes],
               server: Union[IPv4Address, IPv6Address],
               port: int = 53,
               tcp: bool = False) -> dns.message.Message:
    """Get an DNS message with answer with specific query"""
    sock = pydnstest.mock_client.setup_socket(str(server), port, tcp=tcp)
    pydnstest.mock_client.send_query(sock, question)
    return pydnstest.mock_client.get_dns_message(sock)


def string_answer(question: Union[dns.message.Message, bytes],
                  server: Union[IPv4Address, IPv6Address],
                  port: int = 53,
                  tcp: bool = False) -> str:
    """
    Prints answer of a server. Good for generating tests.
    """

    return get_answer(question, server, port, tcp).to_text()


def randomize_case(label: bytes) -> bytes:
    """Randomize case in a DNS name label"""
    chars = list(label.decode("ascii"))
    output = []
    for char in chars:
        if random.randint(0, 1):
            char = char.upper()
        else:
            char = char.lower()
        output.append(char)
    return "".join(output).encode("ascii")


def make_query(name: str, *args, **kwargs) -> dns.message.Message:
    """Proxy for dns.message.make_query with rANdoM-cASe"""
    query = dns.message.make_query(name, *args, **kwargs)
    for label in query.question[0].name.labels:
        label = randomize_case(label)
    return query
