"""Functions for easily send DNS queries and check recieved answers"""
# pylint: disable=C0301
# flake8: noqa

from ipaddress import IPv4Address, IPv6Address
import random
from typing import Union, Set

import dns.message

import pydnstest.matchpart
import pydnstest.mock_client


def send_and_check(question: Union[dns.message.Message, bytes],  # pylint: disable=R0913
                   expected: dns.message.Message,
                   server: Union[IPv4Address, IPv6Address],
                   match_fields: Set[str],
                   port: int = 53,
                   tcp: bool = False) -> bool:
    """Checks if DNS answer recieved for a question from a server matches expected one in specified
    field. See pydnstest.matchpart for more information on match fields

    Returns True on success, raises an exceptions on failure.
    """

    answer = get_answer(question, server, port, tcp)

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


def _print_answer(question: Union[dns.message.Message, bytes],
                  server: Union[IPv4Address, IPv6Address],
                  port: int = 53,
                  tcp: bool = False) -> None:
    """
    Prints answer of a server. Good for generating tests.
    """

    sock = pydnstest.mock_client.setup_socket(str(server), port, tcp=tcp)
    pydnstest.mock_client.send_query(sock, question)
    print(pydnstest.mock_client.get_dns_message(sock).to_text())


def randomize_case(label: bytes) -> bytes:
    """Randomize case in a DNS name label"""
    chars = list(label.decode("ascii"))
    print(chars)
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
