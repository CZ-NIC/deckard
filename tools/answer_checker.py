"""Functions for sending DNS queries and checking recieved answers checking"""
# pylint: disable=C0301
# flake8: noqa

from ipaddress import IPv4Address, IPv6Address
import random
from typing import Iterable, Optional, Set, Union

import dns.message
import dns.flags

import pydnstest.matchpart
import pydnstest.mock_client

def unset_flag(message: dns.message.Message, flag: int) -> dns.message.Message:
    """Unsets given flag in given DNS message."""
    message.flags &= ~flag
    return message


def send_and_check(question: Union[dns.message.Message, bytes],  # pylint: disable=R0913
                   expected: dns.message.Message,
                   server: Union[IPv4Address, IPv6Address],
                   match_fields: Set[str],
                   port: int = 53,
                   tcp: bool = False,
                   timeout: int = pydnstest.mock_client.SOCKET_OPERATION_TIMEOUT,
                   unset_flags: Iterable[int] = tuple()) -> bool:
    """Checks if DNS answer recieved for a question from a server matches expected one in specified
    field. See pydnstest.matchpart for more information on match fields

    Returns True on success, raises an exceptions on failure.
    """
    print(f"Sending query:\n{str(question)}\n")
    answer = get_answer(question, server, port, tcp, timeout=timeout)

    for flag in unset_flags:
        answer = unset_flag(answer, flag)

    print(f"Got answer:\n{answer}\n")
    print(f"Matching:\n{match_fields}\n{expected}\n")
    for field in match_fields:
        pydnstest.matchpart.match_part(expected, answer, field)

    return True


def get_answer(question: Union[dns.message.Message, bytes],
               server: Union[IPv4Address, IPv6Address],
               port: int = 53,
               tcp: bool = False,
               timeout: int = pydnstest.mock_client.SOCKET_OPERATION_TIMEOUT) -> dns.message.Message:
    """Get an DNS message with answer with specific query"""
    sock = pydnstest.mock_client.setup_socket(str(server), port, tcp=tcp)
    with sock:
        pydnstest.mock_client.send_query(sock, question)
        return pydnstest.mock_client.get_dns_message(sock, timeout=timeout)


def string_answer(question: Union[dns.message.Message, bytes],
                  server: Union[IPv4Address, IPv6Address],
                  port: int = 53,
                  tcp: bool = False) -> str:
    """Prints answer of a server. Good for generating tests."""
    return get_answer(question, server, port, tcp).to_text()


def randomize_case(label: bytes) -> bytes:
    """Randomize case in a DNS name label"""
    output = []
    for byte in label:
        if random.randint(0, 1):
            output.append(bytes([byte]).swapcase())
        else:
            output.append(bytes([byte]))
    return b''.join(output)


def make_random_case_query(name: str, *args, **kwargs) -> dns.message.Message:
    """Proxy for dns.message.make_query with rANdoM-cASe"""
    query = dns.message.make_query(name, *args, **kwargs)
    for label in query.question[0].name.labels:
        label = randomize_case(label)
    return query
