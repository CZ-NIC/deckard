#!/usr/bin/env python3
import pcap
import dpkt
import socket
import dns.resolver
import dns
import sys
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString

def class_to_string(rrclass):
    if rrclass == '':
        return rrclass
    else:
        return dns.rdataclass.to_text(rrclass) + " "


def type_to_string(rrtype):
    if rrtype == '':
        return rrtype
    else:
        return dns.rdatatype.to_text(rrtype) + " "


def query_from_rrset(step, flags, rrset):
    q = Query()
    q.set_step(step)
    q.set_flags(flags)
    q.add_question("{0} {1} {2}".format(rrset.name,
                                        class_to_string(rrset.rdclass),
                                        type_to_string(rrset.rdtype)))
    q.add_answer(rrset.to_text())
    return q


def get_superdomain(dname):
        add = set()
        dnames = dname.split('.', 1)
        # Add all levels might be required in future
        if dnames[1] == '':
            return add
        add.add(dnames[1])
        return add

def query_from_packet(dnsmsg):
    # Query
    q = Query()
    q.set_flags(dnsmsg.flags)
    q.set_id(dnsmsg.id)
    #  Question section
    for question in dnsmsg.question:
        q.add_question(question.to_text())
    # Additional section
    for additional in dnsmsg.additional:
        q.add_additional(additional.to_text())
    # Answer section
    for answer in dnsmsg.answer:
        q.add_answer(answer.to_text())
    # Authority section
    for authority in dnsmsg.authority:
        q.add_authoritative(authority.to_text())
    return q

class Query:
    """DNS question class for deckard scenarios"""

    def __init__(self):
        self.question = ""
        self.answer = ""
        self.additional = ""
        self.auth = ""
        self.flags = ""
        self.id = 0
        self.step = 0
        self.top_level = False
        self.covers_sub = False

    def set_step(self, step):
        self.step = step

    def set_flags(self, flags):
        self.flags = dns.flags.to_text(flags)
        if 'QR' in self.flags.split():
            self.flags += " " + dns.rcode.to_text(flags & 0b1111)

    def set_id(self, id):
        self.id = id

    def set_covets_sub(self, covers_sub=True):
        self.covers_sub = covers_sub

    def set_question(self, rrset):
        self.question = ''
        self.add_question(rrset)

    def add_question(self, rrset):
        self.question += rrset + '\n'

    def add_answer(self, rrset):
        self.answer += rrset + '\n'

    def add_additional(self, rrset):
        self.additional += rrset + '\n'

    def add_authoritative(self, rrset):
        self.auth += rrset + '\n'

    def __sort_section__(self, section):
        if section == '':
            return section
        lines = filter(None, section.split('\n'))
        return '\n'.join(sorted(lines)) + '\n'

    def sort_records(self):
        self.answer = self.__sort_section__(self.answer)
        self.question = self.__sort_section__(self.question)
        self.additional = self.__sort_section__(self.additional)
        self.auth = self.__sort_section__(self.auth)

    def to_string(self, server=False):
        question = ''
        answer = ''
        auth = ''
        additional = ''
        self.sort_records()
        if self.question != '':
            question = 'SECTION QUESTION\n' + self.question
        if self.auth != '':
            auth = "SECTION AUTHORITY\n" + self.auth
        if self.additional != '':
            additional = 'SECTION ADDITIONAL\n' + self.additional
        if self.answer != '':
            answer = 'SECTION ANSWER\n' + self.answer
        if server:
            qtype = '' if self.covers_sub else ' qtype'
            subdomain = 'subdomain' if self.covers_sub else 'qname'
            query_string = 'ENTRY_BEGIN\n'
            query_string += 'MATCH {0}{1}\n'.format(subdomain, qtype)
            query_string += 'ADJUST copy_id{0}\n'.format(' copy_query' if self.covers_sub else '')
            query_string += 'REPLY {0}\n'.format(self.flags)
            query_string += '{0}{1}{2}{3}'.format(question, answer, auth, additional)
            query_string += 'ENTRY_END\n'
            return query_string
        if 'QR' in self.flags.split():
            query_string = 'STEP {0} CHECK_ANSWER\n'.format(self.step)
            query_string += 'ENTRY_BEGIN\n'
            query_string += 'MATCH all\n'
            query_string += 'REPLY {0}\n'.format(self.flags)
            query_string += '{0}{1}{2}{3}'.format(question, answer, auth, additional)
            query_string += 'ENTRY_END\n'
            return query_string
        else:
            query_string = 'STEP {0} QUERY\n'.format(self.step)
            query_string += 'ENTRY_BEGIN\n'
            query_string += 'REPLY {0}\n'.format(self.flags)
            query_string += '{0}{1}{2}'.format(question, auth, additional)
            query_string += 'ENTRY_END\n'
            return query_string

    def is_answer(self):
        if 'QR' in self.flags.split():
            return True
        else:
            return False

    def set_top_level(self, top=False):
        self.top_level = top

    def answer_empty(self):
        if self.answer == '' and self.additional == '' and self.auth == '':
            return True
        else:
            return False

    def is_query_for(self, resp):
        if not self.is_answer() and resp.is_answer():
            if self.id == resp.id:
                return True
        return False

    def match(self, other, ip=True):
        if self.question.lower() != other.question.lower():
            return False
        self_lines = self.answer.lower().split('\n')
        other_lines = other.answer.lower().split('\n')
        for self_line, other_line in zip(self_lines, other_lines):
            self_item = self_line.split()
            other_item = other_line.split()
            if ('A' in self_item or 'AAAA' in self_item) and not ip:
                self_item.pop(-1)
                other_item.pop(-1)
            for item1, item2 in zip(self_item, other_item):
                if item1 != item2:
                    return False
        return True

class Server_alternatives:
    """List of name servers covering same domains"""
    def __init__(self):
        # All servers must contain IP of for the others and given NS
        self.names = dict()         # Names of name servers ([ip] = name)
        self.servers = []           # Servers
        #TODO: content: name class flags [TYPES] - only if not A/AAAA, those include allways
        self.content = []           # Queries that every alternative should contain
        self.content_diff = dict()

    def __str__(self):
        names = ''
        servers = ''
        content = ''
        if self.names:
            names = '\n\t\t'.join(sorted(['%s:: %s' % (key, value if value else 'missing')
                                          for (key, value) in self.names.items()]))
        if self.servers:
            servers = '\n\t\t'.join(sorted(str(x) for x in self.servers))
        '''if self.content:
            content = '\n\t\t'.join(sorted(['Query %s Class %s Type %s Flags %s' %
                                     (dns_query, dns_class, dns_type, dns_flags) for
                                     (dns_query, dns_class, dns_type, dns_flags) in self.content]))'''
        if self.content_diff:
            content = '\n\t\t'.join(sorted(['%s:: %s' % (key, value)
                                          for (key, value) in self.content_diff.items()]))
        return "Server alternatives\n\tIP's and names:\n\t\t" +\
               names + '\n\tServers:\n\t\t' + servers + '\n\tContent:\n\t\t' +\
               content + '\n\n'

    def get_server(self, ip):
        for server in self.servers:
            if server.ip == ip:
                return server
        s = Server()
        s.ip = ip
        self.servers.append(s)
        return s

    def add_content(self, name, rdclass, rdtype, flags):
        if isinstance(name, dns.name.Name):
            name = name.to_text().lower()
        for item in self.content:
            if item[0] == name and item[1] == rdclass and item[2] == rdtype and item[3] == flags:
                return
        self.content.append([name,rdclass, rdtype, flags])

    def update_content(self, content):
        for item in content:
            self.add_content(item[0], item[1], item[2], item[3])

    def fix_content_pairs(self):
        # TODO: bez A/AAAA?
        for item in self.content:
            type = dns.rdatatype.A if item[2] == dns.rdatatype.AAAA else dns.rdatatype.AAAA
            self.add_content(item[0], item[1], type, item[3])

    def merge_alternatives(self, alternative):
        self.names.update(alternative.names)
        self.update_content(alternative.content)
        for server in alternative.servers:
            merged = False
            for s in self.servers:
                if server.ip == s.ip:
                    merged = True
                    s.queries = s.queries + server.queries
                    break
            if not merged:
                self.servers.add(server)

    def fill_server(self, server):
        for item in self.content:
            msg = dns.message.make_query(item[0], rdtype=item[2], rdclass=item[1])
            # TODO: TCP / UDP testing for thesis
            resp = ""
            try:
                resp = dns.query.udp(msg, server.ip, 2)
            except:
                # TODO: detect ipv6 not working
                continue
            if resp:
                q = query_from_packet(resp)
                server.add_query(q)

    def fill_servers(self):
        present_s = set()
        # Fill servers with queries
        for server in self.servers:
            present_s.add(server.ip)
            self.fill_server(server)
        # Add missing servers
        ips = self.names.keys()
        ips = ips - present_s

        for ip in ips:
            s = Server()
            s.set_ip(ip)
            self.servers.append(s)
            self.fill_server(s)

    def postprocessing(self):
        ''' Fill missing queries'''
        # TODO: bez A/AAAA?
        self.fix_content_pairs()
        for ip in self.names:
            if self.names[ip]:
                self.add_content(self.names[ip], dns.rdataclass.IN, dns.rdatatype.A, 0)
                self.add_content(self.names[ip], dns.rdataclass.IN, dns.rdatatype.AAAA, 0)
        self.fill_servers()

    def check_answer_difference(self):
        questions = set()
        flags = dict()
        answ = dict()
        auth = dict()
        add = dict()
        for server in self.servers:
            for qry in server.queries:
                qry.sort_records()
                questions.add(qry.question)
                if qry.question not in flags:
                    flags[qry.question] = {qry.flags}
                else:
                    flags[qry.question].add(qry.flags)
                if qry.question not in answ:
                    answ[qry.question] = {qry.answer}

                else:
                    answ[qry.question].add(qry.answer)
                if qry.question not in auth:
                    auth[qry.question] = {qry.auth}
                else:
                    auth[qry.question].add(qry.auth)
                if qry.question not in add:
                    add[qry.question] = {qry.additional}
                else:
                    add[qry.question].add(qry.additional)
        for question in questions:
            if (len(flags[question]) != 1 or len(answ[question]) != 1 or len(auth[question]) != 1 or len(add[question]) != 1):
                self.content_diff[question.rstrip()] = "Flag {0} Answ {1} Auth {2} Add {3}".format(len(flags[question]),
                                                                                    len(answ[question]),
                                                                                        len(auth[question]),
                                                                                            len(add[question]))

class Server:
    """DNS name server class for deckard scenarios"""

    def __init__(self):
        self.ip = ''
        self.min_range = 0
        self.max_range = 100
        # self.final_queries = [] # Records containing domains IP
        self.queries = []       # Records containing NS, self

    def __str__(self):
        return "IP: {0} Queries: {1}\n".format(self.ip, len(self.queries))

    def set_range(self, set_min=0, set_max=100):
        self.min_range = set_min
        self.max_range = set_max

    def set_ip(self, ip):
        self.ip = ip

    def add_query(self, query):
        if self.missing(query):
            self.queries.append(query)

    def missing(self, query):
        for qry in self.queries:
            if qry.match(query, False):
                return False
        return True

    def remove_duplicate(self):
        no_dup = []

        for qry1 in self.queries:
            contains = False
            if not no_dup:
                no_dup.append(qry1)
                continue
            for qry2 in no_dup:
                if qry1.to_string(True).lower() == qry2.to_string(True).lower():
                    contains = True

            if not contains:
                no_dup.append(qry1)

        self.queries = no_dup

    def to_string(self):
        self.remove_duplicate()
        if not self.queries:
            return ""
        server_string = 'RANGE_BEGIN {0} {1}\n'.format(self.min_range, self.max_range)
        server_string += '\tADDRESS {0}\n'.format(self.ip)
        server_string += '\n'
        for qry in self.queries:
            if not qry.covers_sub:
                    server_string += qry.to_string(True) + "\n"
        for qry in self.queries:
            if qry.covers_sub:
                    server_string += qry.to_string(True) + "\n"
        server_string += 'RANGE_END\n'
        return server_string


class Steps:
    """DNS query and response steps for deckard scenarios. TODO: No answer?"""
    def __init__(self):
        self.queries = []

    def add_query(self, query):
        if type(query) is list:
            self.queries.append(query[0])
        else:
            self.queries.append(query)

    def to_string(self):
        step = 1
        steps_string = ""
        for qry in self.queries:
            if not qry.is_answer():
                for resp in self.queries:
                    if qry.is_query_for(resp):
                        qry.set_step(step)
                        step += 1
                        resp.set_step(step)
                        step += 1
                        steps_string = steps_string + qry.to_string() + '\n'
                        steps_string = steps_string + resp.to_string() + '\n\n'
        return steps_string


class Scenario:
    """deckard scenario container"""
    def __init__(self):
        self.steps = Steps()
        self.servers = set()
        self.name = "Unnamed"
        self.other_names = dict() # names from A/AAAA

    def add_name(self, name):
        self.name = name

    def add_step(self, step):
        self.steps.add_query(step)

    def to_string(self):
        scenario_string = ''
        scenario_string += "\tname: \'.\'\n\tstub-addr: 198.41.0.4\n"
        scenario_string += "CONFIG_END\n\nSCENARIO_BEGIN {0}\n\n".format(self.name)
        for alter in self.servers:
            for server in alter.servers:
                scenario_string += server.to_string()
        scenario_string += "\n\n; Sequence of queries made by browser\n\n"
        scenario_string += self.steps.to_string()
        scenario_string += "SCENARIO_END"
        return scenario_string

    def step_from_packet(self, dnsmsg):
        # Query
        q = query_from_packet(dnsmsg)
        self.add_step(q)

    def get_server_alternative(self, ip):
        for servers in self.servers:
            if ip in servers.names.keys():
                return servers

        destination = Server_alternatives()
        if ip not in destination.names:
            destination.names[ip] = ''
        self.servers.add(destination)
        return destination

    def process_a(self, rrset):
        names = dict()
        for item in rrset:
            if item.rdtype == dns.rdatatype.A or item.rdtype == dns.rdatatype.AAAA:
                for rdata in item:
                    names[rdata.address] = item.name.to_text().lower()
        return names

    def process_ns(self, rrset):
        queries = []
        names = set()
        for item in rrset:
            if item.rdtype == dns.rdatatype.NS:
                for rdata in item:
                    queries.append([rdata.target, dns.rdataclass.IN, dns.rdatatype.A, 0])
                    names.add(rdata.target.to_text().lower())
        return queries, names

    def find_ips_for_names(self, rrset, names):
        ips_names = {}
        for item in rrset:
            if item.rdtype == dns.rdatatype.A or item.rdtype == dns.rdatatype.AAAA:
                name = item.name.to_text().lower()
                if name in names:
                    for rdata in item:
                        ips_names[rdata.address] = name
        return ips_names

    def merge_servers(self):
        new_servers = set()
        for server in self.servers:
            merged = False
            for new_s in new_servers:
                if server.names.keys() & new_s.names.keys():
                    new_s.merge_alternatives(server)
                    merged = True
                    break
            if not merged:
                new_servers.add(server)

        self.servers = new_servers


    def update_servers(self, names, queries):
        updated = False
        for server in self.servers:
            if names.keys() & server.names.keys():
                updated = True
                server.names.update(names)
                server.update_content(queries)
                break
        if not updated:
            server = Server_alternatives()
            server.names.update(names)
            server.update_content(queries)
            self.servers.add(server)
        self.merge_servers()

    def postprocessing(self):
        ''' Fill all possible content after all packets were processed'''
        for server in self.servers:
            for ip in self.other_names:
                if ip in server.names.keys():
                    server.names[ip] = self.other_names[ip]
        self.merge_servers()
        for server in self.servers:
            server.postprocessing()

    def check_answer_difference(self):
        for server in self.servers:
            server.check_answer_difference()

    def process_dns(self, dnsmsg, src_ip, dst_ip, step=0):
        # TODO: instead of creating new dnsmsg - use the original, change only name when alternatives
            # TODO: What if they are not present - imitate?
            # TODO: remove CD flag if present
        # TODO: Completing sets of servers, completing content
	    # TODO: NS names from responses
        # Browser - Resolver
        if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
            self.step_from_packet(dnsmsg)
            return

        flags = dnsmsg.flags if dnsmsg.flags and not 16 else dnsmsg.flags - 16

        if dnsmsg.flags & dns.flags.QR == 0:
            destination = self.get_server_alternative(dst_ip)
            # Content - name, class, type, flags - for each server
            for question in dnsmsg.question:
                destination.add_content(question.name, question.rdclass, question.rdtype, flags)
        else:
            alternatives = self.get_server_alternative(src_ip)
            #source = alternatives.get_server(src_ip)
            # Query
            #q = query_from_packet(dnsmsg)
            #source.add_query(q)
            for question in dnsmsg.question:
                alternatives.add_content(question.name, question.rdclass, question.rdtype, flags)
            # Additional section
            queries = []
            names = set()
            names_ips = {}
            # Find A/AAAA names
            for item in [dnsmsg.additional, dnsmsg.answer, dnsmsg.authority]:
                other_names = self.process_a(item)
                self.other_names.update(other_names)
            # Find NS names
            for item in [dnsmsg.additional, dnsmsg.answer, dnsmsg.authority]:
                local_q, local_n = self.process_ns(item)
                queries = queries + local_q
                names = names | local_n
            # Find NS ips
            for item in [dnsmsg.additional, dnsmsg.answer, dnsmsg.authority]:
                local_pn = self.find_ips_for_names(item, names)
                names_ips.update(local_pn)
            if names_ips and queries:
                self.update_servers(names_ips, queries)


def process_file(file):
    file_pcap = open(file, 'rb')
    pcap = dpkt.pcap.Reader(file_pcap)
    sc = Scenario()
    # Process each packet
    for ts, server in pcap:
        # Process layers
        frame = dpkt.sll.SLL(server)
        ip = frame.data
        transport = ip.data
        # Get IP's from IP layer
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        # Process DNS layer
        # Continue only if next layer (dns) present
        if transport.data != b'':
            # Remove DNS over TCP specific length field
            if isinstance(transport, dpkt.tcp.TCP):
                transport.data = transport.data[2:]
            # Parse wire to message
            # noinspection PyBroadException
            try:
                dnsmsg = dns.message.from_wire(transport.data)
            except:  # Skip unsupported dns packet
                continue
            sc.process_dns(dnsmsg, src_ip, dst_ip)
    sc.postprocessing()
    return sc


# TODO: content to class?
# TODO: multiple names per server
# TODO: test on smaller pcaps - takes too long to resolve everything
# TODO: ON/OFF ipv6
# TODO: parallels response difference for 100/1000 qrys
