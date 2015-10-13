import threading
import select
import socket
import os
import time
import dns.message
import dns.rdatatype
import itertools
import struct
import binascii
from dprint import dprint

def recvfrom_msg(stream):
    """ Receive DNS/UDP/TCP message. """
    if stream.type == socket.SOCK_DGRAM:
        data, addr = stream.recvfrom(4096)
    elif stream.type == socket.SOCK_STREAM:
        data = stream.recv(2)
        if len(data) == 0:
            return None, None
        msg_len = struct.unpack_from("!H",data)[0]
        data = ""
        received = 0
        while received < msg_len:
            next_chunk = stream.recv(4096)
            if len(next_chunk) == 0:
                return None, None
            data += next_chunk
            received += len (next_chunk)
        addr = stream.getpeername()[0]
    else:
        raise Exception ("[recvfrom_msg]: unknown socket type '%i'" % stream.type)
    return dns.message.from_wire(data), addr

def sendto_msg(stream, message, addr):
    """ Send DNS/UDP/TCP message. """
    try:
        if stream.type == socket.SOCK_DGRAM:
            stream.sendto(message, addr)
        elif stream.type == socket.SOCK_STREAM:
            data = struct.pack("!H",len(message)) + message
            stream.send(data)
        else:
            raise Exception ("[recvfrom_msg]: unknown socket type '%i'" % stream.type)
    except: # Failure to respond is OK, resolver should recover
        pass

def get_local_addr_str(family, iface):
    """ Returns pattern string for localhost address  """
    if family == socket.AF_INET:
        addr_local_pattern = "127.0.0.{}"
    elif family == socket.AF_INET6:
        addr_local_pattern = "fd00::5357:5f{:02X}"
    else:
        raise Exception("[get_local_addr_str] family not supported '%i'" % family)
    return addr_local_pattern.format(iface)

class AddrMapInfo:
    """ Saves mapping info between adresses from rpl and cwrap adresses """
    def __init__(self, family, local, external):
        self.family   = family
        self.local    = local
        self.external =  external

class TestServer:
    """ This simulates UDP DNS server returning scripted or mirror DNS responses. """

    def __init__(self, scenario, config, d_iface, p_iface):
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
        self.kroot_family = None
        self.default_iface = d_iface
        self.peer_iface = p_iface
        self.set_initial_address()

    def __del__(self):
        """ Cleanup after deletion. """
        if self.active is True:
            self.stop()

    def start(self):
        """ Synchronous start """
        if self.active is True:
            raise Exception('TestServer already started')
        self.active = True
        self.start_srv(self.kroot_local, self.kroot_family)
        self.start_srv(self.kroot_local, self.kroot_family, socket.IPPROTO_TCP)

    def stop(self):
        """ Stop socket server operation. """
        self.active = False
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

    def check_family (self, addr, family):
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
            self.kroot_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.kroot_family, self.default_iface)
            return
        kroot_addr = None
        for k, v in self.config:
            if k == 'stub-addr':
                kroot_addr = v
        if kroot_addr is not None:
            if self.check_family (kroot_addr, socket.AF_INET):
                self.kroot_family = socket.AF_INET
                self.kroot_local = kroot_addr
            elif self.check_family (kroot_addr, socket.AF_INET6):
                self.kroot_family = socket.AF_INET6
                self.kroot_local = kroot_addr
            else:
                raise Exception("[set_initial_adress] Invalid 'stub-addr' address (%s), must be IPv4 or IPv6, check the config")
        else:
            self.kroot_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.kroot_family, self.default_iface)

    def address(self):
        """ Returns opened sockets list """
        addrlist = [];
        for s in self.srv_socks:
            addrlist.append(s.getsockname());
        return addrlist;

    def handle_query(self, client):
        """ Handle incoming queries. """
        client_address = client.getsockname()[0]
        query, addr = recvfrom_msg(client)
        if query is None:
            return False
        dprint ("[ handle_query ]", "incoming query\n%s" % query)
        response = dns.message.make_response(query)
        is_raw_data = False
        if self.scenario is not None:
            response, is_raw_data = self.scenario.reply(query, client_address)
        if response:
            if is_raw_data is False:
                for rr in itertools.chain(response.answer,response.additional,response.question,response.authority):
                    for rd in rr:
                        if rd.rdtype == dns.rdatatype.A:
                            self.start_srv(rd.address, socket.AF_INET)
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            self.start_srv(rd.address, socket.AF_INET6)
                data_to_wire = response.to_wire()
                dprint ("[ handle_query ]", "response\n%s" % response)
            else:
                data_to_wire = response
                dprint ("[ handle_query ]", "raw response found")
        else:
            response = dns.message.make_response(query)
            response.rcode = dns.rcode.SERVFAIL
            data_to_wire = response.to_wire()
            dprint ("[ handle_query ]", "response failed, SERVFAIL")


        sendto_msg(client, data_to_wire, addr)
        return True

    def query_io(self):
        """ Main server process """
        if self.active is False:
            raise Exception("[query_io] Test server not active")
        while self.active is True:
           objects = self.srv_socks + self.connections
           to_read, _, to_error = select.select(objects, [], objects, 0.1)
           for sock in to_read:
              if sock in self.srv_socks:
                  if (sock.proto == socket.IPPROTO_TCP):
                      conn, addr = sock.accept()
                      self.connections.append(conn)
                  else:
                      self.handle_query(sock)
              elif sock in self.connections:
                  if not self.handle_query(sock):
                      sock.close()
                      self.connections.remove(sock)
              else:
                  raise Exception("[query_io] Socket IO internal error {}, exit".format(sock.getsockname()))
           for sock in to_error:
              raise Exception("[query_io] Socket IO error {}, exit".format(sock.getsockname()))

    def start_srv(self, address = None, family = socket.AF_INET, proto = socket.IPPROTO_UDP, port = 53):
        """ Starts listening thread if necessary """

        if family == None:
            family = socket.AF_INET
        if family == socket.AF_INET:
            if address == '' or address is None:
                address = get_local_addr_str(family, self.default_iface)
        elif family == socket.AF_INET6:
            if socket.has_ipv6 is not True:
                raise Exception("[start_srv] IPV6 is not supported")
            if address == '' or address is None:
                address = get_local_addr_str(family, self.default_iface)
        else:
            raise Exception("[start_srv] unsupported protocol family {family}".format(family=family))

        if proto == None:
            proto = socket.IPPROTO_UDP
        if proto == socket.IPPROTO_TCP:
            socktype = socket.SOCK_STREAM
        elif proto == socket.IPPROTO_UDP:
            socktype = socket.SOCK_DGRAM
        else:
            raise Exception("[start_srv] unsupported protocol {protocol}".format(protocol=proto))

        if port == 0 or port is None:
            port = 53

        if (self.thread is None):
            self.thread = threading.Thread(target=self.query_io)
            self.thread.start()

        for srv_sock in self.srv_socks:
            if srv_sock.family == family and srv_sock.getsockname()[0] == address and srv_sock.proto == proto:
                return srv_sock.getsockname()

        addr_info = socket.getaddrinfo(address,port,family,socktype,proto)
        sock = socket.socket(family, socktype, proto)
        sockaddr = addr_info[0][-1]
        sock.bind(sockaddr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if proto == socket.IPPROTO_TCP:
            sock.listen(5)
        self.srv_socks.append(sock)
        sockname = sock.getsockname()
        return sockname, proto

    def play(self):
        saddr = get_local_addr_str(socket.AF_INET,self.default_iface)
        paddr = get_local_addr_str(socket.AF_INET,self.peer_iface)
        self.scenario.play(saddr,paddr)

if __name__ == '__main__':
    # Self-test code
    DEFAULT_IFACE = 0
    CHILD_IFACE = 0
    if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
       DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
    if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254 :
        DEFAULT_IFACE = 10
        os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"]="{}".format(DEFAULT_IFACE)
    # Mirror server
    server = TestServer(None,None,DEFAULT_IFACE,DEFAULT_IFACE)
    server.start()
    print "[==========] Mirror server running at", server.address()
    try:
        while True:
	    time.sleep(0.5)
    except KeyboardInterrupt:
        print "[==========] Shutdown."
        pass
    server.stop()
