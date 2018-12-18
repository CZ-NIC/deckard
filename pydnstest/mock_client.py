"""Module takes care of sending and recieving DNS messages as a mock client"""

from datetime import datetime
import errno
import socket
import struct
import time
from typing import Optional, Tuple, Union

import dns.message


SOCKET_OPERATION_TIMEOUT = 3


def recvfrom_msg(stream, raw=False):
    """
    Receive DNS message from TCP/UDP socket.

    Returns:
        if raw == False: (DNS message object, peer address)
        if raw == True: (blob, peer address)
    """
    if stream.type & socket.SOCK_DGRAM:
        data, addr = stream.recvfrom(4096)
    elif stream.type & socket.SOCK_STREAM:
        data = stream.recv(2)
        if not data:
            return None, None
        msg_len = struct.unpack_from("!H", data)[0]
        data = b""
        received = 0
        while received < msg_len:
            next_chunk = stream.recv(4096)
            if not next_chunk:
                return None, None
            data += next_chunk
            received += len(next_chunk)
        addr = stream.getpeername()[0]
    else:
        raise NotImplementedError("[recvfrom_msg]: unknown socket type '%i'" % stream.type)
    if raw:
        return data, addr
    else:
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


def setup_socket(destination: Tuple[str, int], source=None, tcp=False) -> socket.socket:
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
        if (datetime.now() - tstart).total_seconds() > 5:
            raise RuntimeError("Server took too long to respond")
        try:
            answer, _ = recvfrom_msg(sock, True)
            break
        except OSError as ex:
            if ex.errno == errno.ENOBUFS:
                time.sleep(0.1)
            else:
                raise
    return answer


def get_dns_message(sock: socket.socket) -> dns.message.Message:
    return dns.message.from_wire(get_answer(sock))
