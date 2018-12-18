"""Module takes care of sending and recieving DNS messages as a mock client"""

import errno
import socket
import struct
import time
from typing import Optional, Tuple, Union

import dns.message


SOCKET_OPERATION_TIMEOUT = 5
RECEIVE_MESSAGE_SIZE = 2**16-1
THROTTLE_BY = 0.1


def recvfrom_blob(stream: socket.socket) -> Tuple[bytes, str]:
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


def sendto_msg(stream: socket.socket, message: bytes, addr: Optional[str] = None) -> None:
    """ Send DNS/UDP/TCP message. """
    try:
        if stream.type & socket.SOCK_DGRAM:
            if addr is None:
                stream.send(message)
            else:
                stream.sendto(message, addr)
        elif stream.type & socket.SOCK_STREAM:
            data = struct.pack("!H", len(message)) + message
            stream.send(data)
        else:
            raise NotImplementedError("[sendto_msg]: unknown socket type '%i'" % stream.type)
    except OSError as ex:
        if ex.errno != errno.ECONNREFUSED:  # TODO Investigate how this can happen
            raise


def setup_socket(destination: Tuple[str, int],
                 source: str = None,
                 tcp: bool = False) -> socket.socket:
    family = socket.AF_INET6 if ':' in destination[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if tcp:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    sock.settimeout(SOCKET_OPERATION_TIMEOUT)
    if source:
        sock.bind((source, 0))
    sock.connect(destination)
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
    tstart = datetime.now()
    while True:
        if (datetime.now() - tstart).total_seconds() > SOCKET_OPERATION_TIMEOUT:
            raise RuntimeError("Server took too long to respond")
        try:
            answer, _ = recvfrom_blob(sock)
            break
        except OSError as ex:
            if ex.errno == errno.ENOBUFS:
                time.sleep(0.1)
            else:
                raise
    return answer


def get_dns_message(sock: socket.socket) -> dns.message.Message:
    return dns.message.from_wire(get_answer(sock))
