#!/usr/bin/env python3
import pcap
import dpkt
import socket
import dns.resolver
import dns
import sys


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


class Server:
    """DNS name server class for deckard scenarios"""

    def __init__(self):
        self.ip = set()
        self.min_range = 0
        self.max_range = 100
        self.qrys = []

    def set_range(self, set_min=0, set_max=100):
        self.min_range = set_min
        self.max_range = set_max

    def set_ip(self, ip):
        self.ip.add(ip)

    def set_ips(self, ips):
        self.ip = self.ip.union(ips)

    def add_query(self, query, scope=None, opt=False):
        if scope:
            if not scope & self.ip:
                return False
            else:
                self.ip |= scope
        if type(query) is not list:
            query = [query]
        for qry in query:
            if not opt or self.missing(qry):
                self.qrys.append(qry)
        return True

    def missing(self, query):
        for qry in self.qrys:
            if qry.match(query, False):
                return False
        return True

    def remove_duplicate(self):
        no_dup = []

        for qry1 in self.qrys:
            contains = False
            if not no_dup:
                no_dup.append(qry1)
                continue
            for qry2 in no_dup:
                if qry1.to_string(True).lower() == qry2.to_string(True).lower():
                    contains = True

            if not contains:
                no_dup.append(qry1)

        self.qrys = no_dup

    def to_string(self):
        self.remove_duplicate()
        server_string = 'RANGE_BEGIN {0} {1}\n'.format(self.min_range, self.max_range)
        ips = sorted(self.ip)
        for ip in ips:
            server_string += '\tADDRESS {0}\n'.format(ip)
        server_string += '\n'
        for qry in self.qrys:
            if not qry.covers_sub:
                    server_string += qry.to_string(True) + "\n"
        for qry in self.qrys:
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
        self.root = Server()
        self.steps = Steps()
        self.roots = set()
        self.servers = []
        self.alter = []
        self.name = "Unnamed"
        self.optional = []
        self.A_presence = set()
        self.AAAA_presence = set()
        self.NS_CNAME_SOA_presence = set()
        self.presence = set()

    def add_name(self, name):
        self.name = name

    def add_step(self, step):
        self.steps.add_query(step)

    def add_roots(self, roots):
        if len(roots):
            self.roots |= roots

    def add_alternatives(self, alter):
        if len(alter):
            self.alter.append(alter)

    def add_to_servers(self, source_ip, query, opt=False):
        query_list = query if type(query) is list else [query]
        if (not query_list[0].is_answer()) or query_list[0].answer_empty():
            return

        curr_alter = set()
        if type(source_ip) is set:
            curr_alter |= source_ip
        else:
            curr_alter.add(source_ip)

        for alternatives in self.alter:
            if curr_alter & alternatives:
                curr_alter |= alternatives
                break

        if query_list[0].top_level or self.roots & curr_alter:
            self.roots |= curr_alter
            self.root.add_query(query_list, opt=opt)
        else:
            added = False
            for server in self.servers:
                added = server.add_query(query_list, curr_alter, opt=opt)
                if added:
                    break
            if not added:
                server = Server()
                server.set_ips(curr_alter)
                server.add_query(query_list, opt=opt)
                self.servers.append(server)

    def to_string(self):
        scenario_string = ''
        for i in range(len(self.servers) - 1, -1, -1):
            server = self.servers[i]
            if server.ip & self.roots:
                for qry in server.qrys:
                    self.root.add_query(qry)
                del self.servers[i]
        if len(self.roots) <= 0:
            raise Exception('No root servers found')
        roots = sorted(self.roots)
        scenario_string += "\tname: \'.\'\n\tstub-addr: {0}\n".format(roots[0])
        scenario_string += "CONFIG_END\n\nSCENARIO_BEGIN {0}\n\n".format(self.name)
        self.root.set_ips(self.roots)
        scenario_string += self.root.to_string()
        for server in self.servers:
            scenario_string += server.to_string()
        scenario_string += "\n\n; Sequence of queries made by browser\n\n"
        scenario_string += self.steps.to_string()
        scenario_string += "SCENARIO_END"
        return scenario_string

    def add_optional(self):
        if self.optional:
            for op in self.optional:
                for qry in op[0]:
                    self.add_to_servers(op[1], qry, opt=True)

    def process_dns(self, dnsmsg, src_ip, dst_ip, step=0):
        alternatives = set()
        query_name = ''
        answer_name = set()
        # Query
        q = Query()
        q.set_step(step)
        q.set_flags(dnsmsg.flags)
        q.set_id(dnsmsg.id)
        # Complementary queries - NS
        comp = []
        comp_names = set()
        #  Process question
        for question in dnsmsg.question:
            q.add_question(question.to_text())
            query_name = question.name
        # Additional section
        for additional in dnsmsg.additional:
            q.add_additional(additional.to_text())
            # Complementary operations:
            self.presence.add(additional.name.to_text().lower())
            # Create separate A/AAAA record for each NS server
            comp.append(query_from_rrset(step, dnsmsg.flags, additional))
            # Create list of NS covering same domains
            if additional.rdtype == dns.rdatatype.A or additional.rdtype == dns.rdatatype.AAAA:
                if additional.rdtype == dns.rdatatype.A:
                    self.A_presence.add(additional.name.to_text().lower())
                else:
                    self.AAAA_presence.add(additional.name.to_text().lower())
                for rdata in additional:
                    alternatives.add(rdata.to_text())
        # Answer section
        cname_queries = []
        cnames = []
        for answer in dnsmsg.answer:
            q.add_answer(answer.to_text())
            answer_name.add(answer.name)
            self.presence.add(answer.name.to_text().lower())
            if answer.rdtype == dns.rdatatype.CNAME:
                self.NS_CNAME_SOA_presence.add(answer.name.to_text().lower())
                for rdata in answer:
                    self.presence.add(rdata.target.to_text().lower())
                    cnames.append(rdata.target)
                    comp_names |= get_superdomain(rdata.target.to_text().lower())
            elif answer.rdtype == dns.rdatatype.A or answer.rdtype == dns.rdatatype.AAAA:
                if answer.rdtype == dns.rdatatype.A:
                    self.A_presence.add(answer.name.to_text().lower())
                else:
                    self.AAAA_presence.add(answer.name.to_text().lower())
                if answer.name in cnames:
                    cname_queries.append(query_from_rrset(step, dnsmsg.flags, answer))
            elif answer.rdtype == dns.rdatatype.NS:
                self.NS_CNAME_SOA_presence.add(answer.name.to_text().lower())
                for rdata in answer:
                    comp_names |= get_superdomain(rdata.target.to_text().lower())
        # Authority section
        for authority in dnsmsg.authority:
            q.add_authoritative(authority.to_text())
            if authority.rdtype == dns.rdatatype.NS:
                relation = authority.name.fullcompare(query_name)
                if relation[0] == dns.name.NAMERELN_SUPERDOMAIN and query_name not in answer_name:
                    q.set_covets_sub(True)
                    q.set_question("{0} IN NS".format(authority.name))
                self.NS_CNAME_SOA_presence.add(authority.name.to_text().lower())
                self.presence.add(authority.name.to_text().lower())
                for rdata in authority:
                    comp_names |= get_superdomain(rdata.target.to_text().lower())
            if authority.name.to_text() == '.':
                q.set_top_level(True)
                self.add_roots(alternatives)
            elif authority.name.split(2)[1] == authority.name:
                q.set_top_level(True)
        # Add NS responses for higher level of each NS server
        for a in comp_names:
            cn = Query()
            cn.set_flags(dnsmsg.flags)
            # noinspection PyBroadException
            try:
                resp = dns.resolver.query(a, 2, 1).response
                for qu in resp.question:
                    cn.add_question(qu.to_text())
                for qu in resp.authority:
                    cn.add_authoritative(qu.to_text())
                for qu in resp.additional:
                    cn.add_additional(qu.to_text())
                for qu in resp.answer:
                    cn.add_answer(qu.to_text())
                comp.append(cn)
            except:
                pass
        # Decide what to send
        if src_ip == "127.0.0.1" and dst_ip == "127.0.0.1":
            self.add_step(q)
        else:
            if cname_queries:
                self.optional.append([cname_queries, src_ip])
            self.add_alternatives(alternatives)
            self.add_to_servers(src_ip, q)
            if comp:  # Add complentary records to parent and child zone
                self.add_to_servers(src_ip, comp)
                self.add_to_servers(alternatives, comp)


def process_file(file, name):
    file_pcap = open(file, 'rb')
    pcap = dpkt.pcap.Reader(file_pcap)
    sc = Scenario()
    sc.add_name(name)
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
    sc.add_optional()
    # Return scenario
    print(sc.to_string())


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("Invalid argument count\n")
        sys.exit(1)
    try:
        process_file(sys.argv[1], sys.argv[2])
    except Exception as e:
        print(e)
        exit(1)
    exit(0)


if __name__ == "__main__":
    main(sys.argv)
