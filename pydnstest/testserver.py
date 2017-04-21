from __future__ import absolute_import

import argparse
import fileinput
import logging
import threading
import select
import socket
import os
import time
import dns.message
import dns.rdatatype
import itertools

from pydnstest import scenario


def get_local_addr_str(family, iface):
    """ Returns pattern string for localhost address  """
    if family == socket.AF_INET:
        addr_local_pattern = "127.0.0.{}"
    elif family == socket.AF_INET6:
        addr_local_pattern = "fd00::5357:5f{:02X}"
    else:
        raise NotImplementedError("[get_local_addr_str] family not supported '%i'" % family)
    return addr_local_pattern.format(iface)


class AddrMapInfo:
    """ Saves mapping info between adresses from rpl and cwrap adresses """

    def __init__(self, family, local, external):
        self.family = family
        self.local = local
        self.external = external


class TestServer:
    """ This simulates UDP DNS server returning scripted or mirror DNS responses. """

    def __init__(self, scenario, config, d_iface):
        """ Initialize server instance. """
        self.thread = None
        self.srv_socks = []
        self.client_socks = []
        self.connections = []
        self.active = False
        self.scenario = scenario
        self.config = config
        self.addr_map = []
        self.start_iface = 2
        self.cur_iface = self.start_iface
        self.kroot_local = None
        self.addr_family = None
        self.default_iface = d_iface
        self.set_initial_address()

    def __del__(self):
        """ Cleanup after deletion. """
        if self.active is True:
            self.stop()

    def start(self, port=53):
        """ Synchronous start """
        if self.active is True:
            raise Exception('TestServer already started')
        self.active = True
        self.addr, _ = self.start_srv((self.kroot_local, port), self.addr_family)
        self.start_srv(self.addr, self.addr_family, socket.IPPROTO_TCP)
        self._bind_sockets()

    def stop(self):
        """ Stop socket server operation. """
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

    def check_family(self, addr, family):
        """ Determines if address matches family """
        test_addr = None
        try:
            n = socket.inet_pton(family, addr)
            test_addr = socket.inet_ntop(family, n)
        except socket.error:
            return False
        return True

    def set_initial_address(self):
        """ Set address for starting thread """
        if self.config is None:
            self.addr_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.addr_family, self.default_iface)
            return
        # Default address is localhost
        kroot_addr = None
        for k, v in self.config:
            if k == 'stub-addr':
                kroot_addr = v
        if kroot_addr is not None:
            if self.check_family(kroot_addr, socket.AF_INET):
                self.addr_family = socket.AF_INET
                self.kroot_local = kroot_addr
            elif self.check_family(kroot_addr, socket.AF_INET6):
                self.addr_family = socket.AF_INET6
                self.kroot_local = kroot_addr
        else:
            self.addr_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.addr_family, self.default_iface)

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
        query, client_addr = scenario.recvfrom_msg(client)
        if query is None:
            return False
        log.debug('server %s received query from %s: %s', server_addr, client_addr, query)
        response, is_raw_data = self.scenario.reply(query, server_addr)
        if response:
            if is_raw_data is False:
                data_to_wire = response.to_wire(max_size=65535)
                log.debug('response: %s', response)
            else:
                data_to_wire = response
                log.debug('raw response not printed')
        else:
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            data_to_wire = response.to_wire()
            self.undefined_answers += 1
            self.scenario.current_step.log.error(
                'server %s has no response for question %s, answering with SERVFAIL',
                server_addr,
                '; '.join([str(rr) for rr in query.question]))

        scenario.sendto_msg(client, data_to_wire, client_addr)
        return True

    def query_io(self):
        """ Main server process """
        self.undefined_answers = 0
        if self.active is False:
            raise Exception("[query_io] Test server not active")
        while self.active is True:
            objects = self.srv_socks + self.connections
            to_read, _, to_error = select.select(objects, [], objects, 0.1)
            for sock in to_read:
                if sock in self.srv_socks:
                    if sock.proto == socket.IPPROTO_TCP:
                        conn, addr = sock.accept()
                        self.connections.append(conn)
                    else:
                        self.handle_query(sock)
                elif sock in self.connections:
                    if not self.handle_query(sock):
                        sock.close()
                        self.connections.remove(sock)
                else:
                    raise Exception(
                        "[query_io] Socket IO internal error {}, exit".format(sock.getsockname()))
            for sock in to_error:
                raise Exception("[query_io] Socket IO error {}, exit".format(sock.getsockname()))

    def start_srv(self, address=None, family=socket.AF_INET, proto=socket.IPPROTO_UDP):
        """ Starts listening thread if necessary """
        assert family
        assert proto
        if family == socket.AF_INET:
            if address[0] is None:
                address = (get_local_addr_str(family, self.default_iface), 53)
        elif family == socket.AF_INET6:
            if socket.has_ipv6 is not True:
                raise NotImplementedError("[start_srv] IPv6 is not supported by socket {0}"
                                          .format(socket))
            if address[0] is None:
                address = (get_local_addr_str(family, self.default_iface), 53)
        else:
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

        for srv_sock in self.srv_socks:
            if (srv_sock.family == family
                    and srv_sock.getsockname() == address
                    and srv_sock.proto == proto):
                return srv_sock.getsockname()

        sock = socket.socket(family, socktype, proto)
        sock.bind(address)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            self.start_srv((rd.address, 53), socket.AF_INET6)

    def play(self, subject_addr):
        paddr = get_local_addr_str(self.scenario.sockfamily, subject_addr)
        self.scenario.play({'': (paddr, 53)})


def empty_test_case():
    """
    Return (scenario, config) pair which answers to any query on 127.0.0.10.
    """
    # Mirror server
    entry = scenario.Entry()
    entry.set_match([])  # match everything
    entry.set_adjust(['copy_id', 'copy_query'])

    rng = scenario.Range(0, 100)
    rng.add(entry)
    rng.addresses.add('127.0.0.10')

    step = scenario.Step(1, 'QUERY', [])

    test_scenario = scenario.Scenario('empty replies')
    test_scenario.ranges.append(rng)
    test_scenario.steps.append(step)
    test_scenario.current_step = step

    test_config = [('stub-addr', '127.0.0.10')]

    return (test_scenario, test_config)

if __name__ == '__main__':
    # Self-test code
    # Usage: $PYTHON -m pydnstest.testserver
    logging.basicConfig(level=logging.DEBUG)
    argparser = argparse.ArgumentParser()
    argparser.add_argument('--scenario', help='path to test scenario',
                           required=False)
    argparser.add_argument('--step', help='step # in the scenario (default: first)',
                           required=False, type=int)
    args = argparser.parse_args()
    if args.scenario:
        test_scenario, test_config = scenario.parse_file(fileinput.input(args.scenario))
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

    DEFAULT_IFACE = 0
    CHILD_IFACE = 0
    if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
        DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
    if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254:
        DEFAULT_IFACE = 10
        os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"] = "{}".format(DEFAULT_IFACE)

    server = TestServer(test_scenario, test_config, DEFAULT_IFACE)
    server.start()

    logging.info("[==========] Mirror server running at %s", server.address())
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        logging.info("[==========] Shutdown.")
        pass
    server.stop()
