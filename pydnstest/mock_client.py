"""Module takes care of sending and recieving DNS messages as a mock client"""

from datetime import datetime
import errno
import socket
import struct
import time
from typing import Optional, Tuple, Union

import dns.message
import dns.inet


SOCKET_OPERATION_TIMEOUT = 5
RECEIVE_MESSAGE_SIZE = 2**16-1
THROTTLE_BY = 0.1


def handle_socket_timeout(sock: socket.socket, deadline: float):
    # deadline is always time.monotonic
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("Server took too long to respond")
    sock.settimeout(remaining)


def recv_n_bytes_from_tcp(stream: socket.socket, n: int, deadline: float) -> bytes:
    # deadline is always time.monotonic
    data = b""
    while n != 0:
        handle_socket_timeout(stream, deadline)
        chunk = stream.recv(n)
        # Empty bytes from socket.recv mean that socket is closed
        if not chunk:
            raise OSError()
        n -= len(chunk)
        data += chunk
    return data


def recvfrom_blob(sock: socket.socket) -> Tuple[bytes, str]:
    """
    Receive DNS message from TCP/UDP socket.
    """

    # deadline is always time.monotonic
    deadline = time.monotonic() + SOCKET_OPERATION_TIMEOUT

    while True:
        try:
            if sock.type & socket.SOCK_DGRAM:
                handle_socket_timeout(sock, deadline)
                data, addr = sock.recvfrom(RECEIVE_MESSAGE_SIZE)
            elif sock.type & socket.SOCK_STREAM:
                # First 2 bytes of TCP packet are the size of the message
                # See https://tools.ietf.org/html/rfc1035#section-4.2.2
                data = recv_n_bytes_from_tcp(sock, 2, deadline)
                msg_len = struct.unpack_from("!H", data)[0]
                data = recv_n_bytes_from_tcp(sock, msg_len, deadline)
                addr = sock.getpeername()[0]
            else:
                raise NotImplementedError("[recvfrom_blob]: unknown socket type '%i'" % sock.type)
            return data, addr
        except OSError as ex:
            if ex.errno == errno.ENOBUFS:
                time.sleep(0.1)
            else:
                raise

def recvfrom_msg(sock: socket.socket) -> Tuple[dns.message.Message, str]:
    data, addr = recvfrom_blob(sock)
    msg = dns.message.from_wire(data, one_rr_per_rrset=True)
    return msg, addr


def sendto_msg(sock: socket.socket, message: bytes, addr: Optional[str] = None) -> None:
    """ Send DNS/UDP/TCP message. """
    try:
        if sock.type & socket.SOCK_DGRAM:
            if addr is None:
                sock.send(message)
            else:
                sock.sendto(message, addr)
        elif sock.type & socket.SOCK_STREAM:
            data = struct.pack("!H", len(message)) + message
            sock.send(data)
        else:
            raise NotImplementedError("[sendto_msg]: unknown socket type '%i'" % sock.type)
    except OSError as ex:
        if ex.errno != errno.ECONNREFUSED:  # TODO Investigate how this can happen
            raise


def setup_socket(address: str,
                 port: int,
                 source: str = None,
                 tcp: bool = False) -> socket.socket:
    family = dns.inet.af_for_address(address)
    sock = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if tcp:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    sock.settimeout(SOCKET_OPERATION_TIMEOUT)
    if source:
        sock.bind((source, 0))
    sock.connect((address, port))
    return sock


def send_query(sock: socket.socket, query: Union[dns.message.Message, bytes]) -> None:
    message = query if isinstance(query, bytes) else query.to_wire()
    while True:
        try:
            sendto_msg(sock, message)
            break
        except OSError as ex:
            # ENOBUFS, throttle sending
            if ex.errno == errno.ENOBUFS:
                time.sleep(0.1)
            else:
                raise


def get_answer(sock: socket.socket) -> bytes:
    """ Compatibility function """
    answer, _ = recvfrom_blob(sock)
    return answer


def get_dns_message(sock: socket.socket) -> dns.message.Message:
    return dns.message.from_wire(get_answer(sock))
