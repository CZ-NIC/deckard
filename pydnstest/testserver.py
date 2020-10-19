import argparse
import itertools
import logging
import os
import random
import signal
import selectors
import socket
import sys
import threading
import time

import dns.message
import dns.rdatatype

from pydnstest import scenario, mock_client
from networking import InterfaceManager


class TestServer:
    """ This simulates UDP DNS server returning scripted or mirror DNS responses. """

    RETRIES_ON_BIND = 3

    def __init__(self, test_scenario, addr_family,
                 deckard_address=None, if_manager=None):
        """ Initialize server instance. """
        self.thread = None
        self.srv_socks = []
        self.client_socks = []
        self.connections = []
        self.active = False
        self.active_lock = threading.Lock()
        self.condition = threading.Condition()
        self.scenario = test_scenario
        self.scenario.deckard_address = deckard_address
        self.addr_map = []
        self.start_iface = 2
        self.cur_iface = self.start_iface
        self.addr_family = addr_family
        self.undefined_answers = 0
        self.if_manager = if_manager

    def __del__(self):
        """ Cleanup after deletion. """
        with self.active_lock:
            active = self.active
        if active:
            self.stop()

    def start(self):
        """ Synchronous start """
        with self.active_lock:
            if self.active:
                raise Exception('TestServer already started')
        with self.active_lock:
            self.active = True

        self._bind_sockets()

    def stop(self):
        """ Stop socket server operation. """
        with self.active_lock:
            self.active = False
        if self.thread:
            self.thread.join()
        for conn in self.connections:
            conn.close()
        for srv_sock in self.srv_socks:
            srv_sock.close()
        for client_sock in self.client_socks:
            client_sock.close()
        self.client_socks = []
        self.srv_socks = []
        self.connections = []
        self.scenario = None

    def address(self):
        """ Returns opened sockets list """
        addrlist = []
        for s in self.srv_socks:
            addrlist.append(s.getsockname())
        return addrlist

    def handle_query(self, client):
        """
        Receive query from client socket and send an answer.

        Returns:
            True if client socket should be closed by caller
            False if client socket should be kept open
        """
        log = logging.getLogger('pydnstest.testserver.handle_query')
        server_addr = client.getsockname()[0]
        query, client_addr = mock_client.recvfrom_msg(client)
        if query is None:
            return False
        log.debug('server %s received query from %s: %s', server_addr, client_addr, query)

        message = self.scenario.reply(query, server_addr)
        if not message:
            log.debug('ignoring')
            return True
        elif isinstance(message, scenario.DNSReplyServfail):
            self.undefined_answers += 1
            self.scenario.current_step.log.error(
                'server %s has no response for question %s, answering with SERVFAIL',
                server_addr,
                '; '.join([str(rr) for rr in query.question]))
        else:
            log.debug('response: %s', message)

        mock_client.sendto_msg(client, message.to_wire(), client_addr)
        return True

    def query_io(self):
        """ Main server process """
        self.undefined_answers = 0
        with self.active_lock:
            if not self.active:
                raise Exception("[query_io] Test server not active")
        while True:
            with self.condition:
                self.condition.notify()
            with self.active_lock:
                if not self.active:
                    break
            objects = self.srv_socks + self.connections
            sel = selectors.DefaultSelector()
            for obj in objects:
                sel.register(obj, selectors.EVENT_READ)
            items = sel.select(0.1)
            for key, event in items:
                sock = key.fileobj
                if event & selectors.EVENT_READ:
                    if sock in self.srv_socks:
                        if sock.proto == socket.IPPROTO_TCP:
                            conn, _ = sock.accept()
                            self.connections.append(conn)
                        else:
                            self.handle_query(sock)
                    elif sock in self.connections:
                        if not self.handle_query(sock):
                            sock.close()
                            self.connections.remove(sock)
                    else:
                        raise Exception(
                            "[query_io] Socket IO internal error {}, exit"
                            .format(sock.getsockname()))
                else:
                    raise Exception("[query_io] Socket IO error {}, exit"
                                    .format(sock.getsockname()))

    def start_srv(self, address, family, proto=socket.IPPROTO_UDP):
        """ Starts listening thread if necessary """
        assert address
        assert address[0]  # host
        assert address[1]  # port
        assert family
        assert proto
        if family == socket.AF_INET6:
            if not socket.has_ipv6:
                raise NotImplementedError("[start_srv] IPv6 is not supported by socket {0}"
                                          .format(socket))
        elif family != socket.AF_INET:
            raise NotImplementedError("[start_srv] unsupported protocol family {0}".format(family))

        if proto == socket.IPPROTO_TCP:
            socktype = socket.SOCK_STREAM
        elif proto == socket.IPPROTO_UDP:
            socktype = socket.SOCK_DGRAM
        else:
            raise NotImplementedError("[start_srv] unsupported protocol {0}".format(proto))

        if self.thread is None:
            self.thread = threading.Thread(target=self.query_io)
            self.thread.start()
            with self.condition:
                self.condition.wait()

        for srv_sock in self.srv_socks:
            if (srv_sock.family == family
                    and srv_sock.getsockname() == address
                    and srv_sock.proto == proto):
                return srv_sock.getsockname()

        sock = socket.socket(family, socktype, proto)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Add address to interface when running from Deckard
        if self.if_manager is not None:
            if address[0] not in self.if_manager.added_addresses:
                self.if_manager.add_address(address[0])

        # A lot of addresses are added to the interface while runnning from Deckard in
        # the small amount of time which caused ocassional hiccups while binding to them
        # right afterwards in testing. Therefore, we retry a few times.
        ex = None
        for i in range(self.RETRIES_ON_BIND):
            try:
                sock.bind(address)
                break
            except OSError as e:
                # Exponential backoff
                time.sleep((2 ** i) + random.random())
                ex = e
                continue
        else:
            print(ex, address)
            raise ex

        if proto == socket.IPPROTO_TCP:
            sock.listen(5)
        self.srv_socks.append(sock)
        sockname = sock.getsockname()
        return sockname, proto

    def _bind_sockets(self):
        """
        Bind test server to port 53 on all addresses referenced by test scenario.
        """
        # Bind to test servers
        for r in self.scenario.ranges:
            for addr in r.addresses:
                family = socket.AF_INET6 if ':' in addr else socket.AF_INET
                self.start_srv((addr, 53), family)
                self.start_srv((addr, 53), family, proto=socket.IPPROTO_TCP)

        # Bind addresses in ad-hoc REPLYs
        for s in self.scenario.steps:
            if s.type == 'REPLY':
                reply = s.data[0].message
                for rr in itertools.chain(reply.answer,
                                          reply.additional,
                                          reply.question,
                                          reply.authority):
                    for rd in rr:
                        if rd.rdtype == dns.rdatatype.A:
                            self.start_srv((rd.address, 53), socket.AF_INET)
                            self.start_srv((rd.address, 53), socket.AF_INET, proto=socket.IPPROTO_TCP)
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            self.start_srv((rd.address, 53), socket.AF_INET6)
                            self.start_srv((rd.address, 53), socket.AF_INET6, proto=socket.IPPROTO_TCP)

    def play(self, subject_addr):
        self.scenario.play({'': (subject_addr, 53)})


def empty_test_case():
    """
    Return (scenario, config) pair which answers to any query on 127.0.0.10.
    """
    # Mirror server
    empty_test_path = os.path.dirname(os.path.realpath(__file__)) + "/empty.rpl"
    test_config = {'ROOT_ADDR': '127.0.0.10',
                   '_SOCKET_FAMILY': socket.AF_INET}
    return scenario.parse_file(empty_test_path)[0], test_config


def standalone_self_test():
    """
    Self-test code

    Usage:
    unshare -rn $PYTHON -m pydnstest.testserver --help
    """
    logging.basicConfig(level=logging.DEBUG)
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--scenario', help='absolute path to test scenario',
                           required=False)
    argparser.add_argument('--step', help='step # in the scenario (default: first)',
                           required=False, type=int)
    args = argparser.parse_args()
    if args.scenario:
        test_scenario, test_config_text = scenario.parse_file(args.scenario)
        test_config = scenario.parse_config(test_config_text, True, os.getcwd())
    else:
        test_scenario, test_config = empty_test_case()

    if args.step:
        for step in test_scenario.steps:
            if step.id == args.step:
                test_scenario.current_step = step
        if not test_scenario.current_step:
            raise ValueError('step ID %s not found in scenario' % args.step)
    else:
        test_scenario.current_step = test_scenario.steps[0]

    if_manager = InterfaceManager(interface="testserver")
    server = TestServer(test_scenario, test_config['_SOCKET_FAMILY'], if_manager=if_manager)
    server.start()

    logging.info("[==========] Mirror server running at %s", server.address())

    def kill(signum, frame):  # pylint: disable=unused-argument
        logging.info("[==========] Shutdown.")
        server.stop()
        sys.exit(128 + signum)

    signal.signal(signal.SIGINT, kill)
    signal.signal(signal.SIGTERM, kill)

    while True:
        time.sleep(0.5)


if __name__ == '__main__':
    # this is done to avoid creating global variables
    standalone_self_test()
