import dns.message
import dns.rrset
import dns.rcode
import dns.dnssec
import dns.tsigkeyring
import binascii
import socket, struct
import os, sys, errno
import itertools, random, string
import time
from datetime import datetime
from dprint import dprint
from testserver import recvfrom_msg, sendto_msg

# If PCAP is pointed to a file, queries/responses from the test are captured
g_pcap = None
if 'PCAP' in os.environ:
    import dpkt
    g_pcap = dpkt.pcap.Writer(open(os.environ['PCAP'], 'wb'))
def log_packet(sock, buf, query = True):
    """ Fake underlying layers and store packet in a pcap. """
    if not g_pcap:
        return
    src, dst = (sock.getpeername()[0], 53), sock.getsockname()
    if query:
        src, dst = sock.getsockname(), (sock.getpeername()[0], 53)
    # Synthesise IP/UDP/Eth layers
    transport = dpkt.udp.UDP(data = buf, dport = dst[1], sport = src[1])
    transport.ulen = len(transport)
    ip = dpkt.ip.IP(src = socket.inet_pton(sock.family, src[0]),
                    dst = socket.inet_pton(sock.family, dst[0]), p = dpkt.ip.IP_PROTO_UDP)
    ip.data = transport
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(data = ip)
    g_pcap.writepkt(eth.pack())

# Global statistics
g_rtt = 0.0
g_nqueries = 0

#
# Element comparators
#

def create_rr(owner, args, ttl = 3600, rdclass = 'IN', origin = '.'):
    """ Parse RR from tokenized string. """
    if not owner.endswith('.'):
        owner += origin
    try:
        ttl = dns.ttl.from_text(args[0])
        args.pop(0)
    except:
        pass  # optional
    try:
        rdclass = dns.rdataclass.from_text(args[0])
        args.pop(0)
    except:
        pass  # optional
    rdtype = args.pop(0)
    rr = dns.rrset.from_text(owner, ttl, rdclass, rdtype)
    if len(args) > 0:
        if (rr.rdtype == dns.rdatatype.DS):
            # convert textual algorithm identifier to number
            args[1] = str(dns.dnssec.algorithm_from_text(args[1]))
        rd = dns.rdata.from_text(rr.rdclass, rr.rdtype, ' '.join(args), origin=dns.name.from_text(origin), relativize=False)
        rr.add(rd)
    return rr

def compare_rrs(expected, got):
    """ Compare lists of RR sets, throw exception if different. """
    for rr in expected:
        if rr not in got:
            raise Exception("expected record '%s'" % rr.to_text())
    for rr in got:
        if rr not in expected:
            raise Exception("unexpected record '%s'" % rr.to_text())
    return True

def compare_val(expected, got):
    """ Compare values, throw exception if different. """
    if expected != got:
        raise Exception("expected '%s', got '%s'" % (expected, got))
    return True

def compare_sub(got, expected):
    """ Check if got subdomain of expected, throw exception if different. """
    if not expected.is_subdomain(got):
        raise Exception("expected subdomain of '%s', got '%s'" % (expected, got))
    return True

def replay_rrs(rrs, nqueries, destination, args = []):
    """ Replay list of queries and report statistics. """
    navail, queries = len(rrs), []
    chunksize = 16
    for i in range(nqueries if 'RAND' in args else navail):
        rr = rrs[i % navail]
        name = rr.name
        if 'RAND' in args:
            prefix = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(8)])
            name = prefix + '.' + rr.name.to_text()
        msg = dns.message.make_query(name, rr.rdtype, rr.rdclass)
        if 'DO' in args:
            msg.want_dnssec(True)
        queries.append(msg.to_wire())
    # Make a UDP connected socket to the destination
    tstart = datetime.now()
    family = socket.AF_INET6 if ':' in destination[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.connect(destination)
    sock.setblocking(False)
    # Play the query set
    # @NOTE: this is only good for relative low-speed replay
    rcvbuf = bytearray('\x00' * 512)
    nsent, nrcvd, nwait, navail = 0, 0, 0, len(queries)
    fdset = [sock]
    import select
    while nsent - nwait < nqueries:
        to_read, to_write, _ = select.select(fdset, fdset if nwait < chunksize else [], [], 0.5)
        if len(to_write) > 0:
            try:
                while nsent < nqueries and nwait < chunksize:
                    sock.send(queries[nsent % navail])
                    nwait += 1
                    nsent += 1
            except:
                pass # EINVAL
        if len(to_read) > 0:
            try:
                while nwait > 0:
                    sock.recv_into(rcvbuf)
                    nwait -= 1
                    nrcvd += 1
            except:
                pass
        if len(to_write) == 0 and len(to_read) == 0:
            nwait = 0 # Timeout, started dropping packets
            break
    return nsent, nrcvd

class Entry:
    """
    Data entry represents scripted message and extra metadata, notably match criteria and reply adjustments.
    """

    # Globals
    default_ttl = 3600
    default_cls = 'IN'
    default_rc = 'NOERROR'

    def __init__(self, lineno = 0):
        """ Initialize data entry. """
        self.match_fields = ['opcode', 'qtype', 'qname']
        self.adjust_fields = ['copy_id']
        self.origin = '.'
        self.message = dns.message.Message()
        self.message.use_edns(edns = 0, payload = 4096)
        self.sections = []
        self.is_raw_data_entry = False
        self.raw_data_pending = False
        self.raw_data = None
        self.lineno = lineno
        self.mandatory = False
        self.fired = 0;

    def match_part(self, code, msg):
        """ Compare scripted reply to given message using single criteria. """
        if code not in self.match_fields and 'all' not in self.match_fields:
            return True
        expected = self.message
        if code == 'opcode':
            return compare_val(expected.opcode(), msg.opcode())
        elif code == 'qtype':
            if len(expected.question) == 0:
                return True
            return compare_val(expected.question[0].rdtype, msg.question[0].rdtype)
        elif code == 'qname':
            if len(expected.question) == 0:
                return True
            qname = dns.name.from_text(msg.question[0].name.to_text().lower())
            return compare_val(expected.question[0].name, qname)
        elif code == 'subdomain':
            if len(expected.question) == 0:
                return True
            qname = dns.name.from_text(msg.question[0].name.to_text().lower())
            return compare_sub(expected.question[0].name, qname)
        elif code == 'flags':
            return compare_val(dns.flags.to_text(expected.flags), dns.flags.to_text(msg.flags))
        elif code == 'rcode':
            return compare_val(dns.rcode.to_text(expected.rcode()), dns.rcode.to_text(msg.rcode()))
        elif code == 'question':
            return compare_rrs(expected.question, msg.question)
        elif code == 'answer' or code == 'ttl':
            return compare_rrs(expected.answer, msg.answer)
        elif code == 'authority':
            return compare_rrs(expected.authority, msg.authority)
        elif code == 'additional':
            return compare_rrs(expected.additional, msg.additional)
        elif code == 'edns':
            if msg.edns != expected.edns:
                raise Exception('expected EDNS %d, got %d' % (expected.edns, msg.edns))
            if msg.payload != expected.payload:
                raise Exception('expected EDNS bufsize %d, got %d' % (expected.payload, msg.payload))
        elif code == 'nsid':
            nsid_opt = None
            for opt in expected.options:
                if opt.otype == dns.edns.NSID:
                    nsid_opt = opt
                    break
            # Find matching NSID
            for opt in msg.options:
                if opt.otype == dns.edns.NSID:
                    if nsid_opt == None:
                        raise Exception('unexpected NSID value "%s"' % opt.data)
                    if opt == nsid_opt:
                        return True
                    else:
                        raise Exception('expected NSID "%s", got "%s"' % (nsid_opt.data, opt.data))
            if nsid_opt:
                raise Exception('expected NSID "%s"' % nsid_opt.data)
        else:
            raise Exception('unknown match request "%s"' % code)

    def match(self, msg):
        """ Compare scripted reply to given message based on match criteria. """
        match_fields = self.match_fields
        if 'all' in match_fields:
            match_fields.remove('all')
            match_fields += ['flags'] + ['rcode'] + self.sections
        for code in match_fields:
            try:
                res = self.match_part(code, msg)
            except Exception as e:
                errstr = '%s in the response:\n%s' % (str(e), msg.to_text())
                raise Exception("line %d, \"%s\": %s" % (self.lineno, code, errstr))

    def cmp_raw(self, raw_value):
        if self.is_raw_data_entry is False:
            raise Exception("entry.cmp_raw() misuse")
        expected = None
        if self.raw_data is not None:
            expected = binascii.hexlify(self.raw_data)
        got = None
        if raw_value is not None:
            got = binascii.hexlify(raw_value)
        if expected != got:
            print("expected '",expected,"', got '",got,"'")
            raise Exception("comparsion failed")

    def set_match(self, fields):
        """ Set conditions for message comparison [all, flags, question, answer, authority, additional, edns] """
        self.match_fields = fields

    def adjust_reply(self, query):
        """ Copy scripted reply and adjust to received query. """
        answer = dns.message.from_wire(self.message.to_wire(),xfr=self.message.xfr)
        answer.use_edns(query.edns, query.ednsflags, options = self.message.options)
        if 'copy_id' in self.adjust_fields:
            answer.id = query.id
            # Copy letter-case if the template has QD
            if len(answer.question) > 0:
                answer.question[0].name = query.question[0].name
        if 'copy_query' in self.adjust_fields:
            answer.question = query.question
        # Re-set, as the EDNS might have reset the ext-rcode
        answer.set_rcode(self.message.rcode())
        return answer

    def set_adjust(self, fields):
        """ Set reply adjustment fields [copy_id, copy_query] """
        self.adjust_fields = fields

    def set_reply(self, fields):
        """ Set reply flags and rcode. """
        eflags = []
        flags = []
        rcode = dns.rcode.from_text(self.default_rc)
        for code in fields:
            if code == 'DO':
                eflags.append(code)
                continue
            try:
                rcode = dns.rcode.from_text(code)
            except:
                flags.append(code)
        self.message.flags = dns.flags.from_text(' '.join(flags))
        self.message.want_dnssec('DO' in eflags)
        self.message.set_rcode(rcode)

    def set_edns(self, fields):
        """ Set EDNS version and bufsize. """
        version = 0
        bufsize = 4096
        if len(fields) > 0 and fields[0].isdigit():
            version = int(fields.pop(0))
        if len(fields) > 0 and fields[0].isdigit():
            bufsize = int(fields.pop(0))
        if bufsize == 0:
            self.message.use_edns(False)
            return
        opts = []
        for v in fields:
            k, v = tuple(v.split('=')) if '=' in v else (v, True)
            if k.lower() == 'nsid':
                opts.append(dns.edns.GenericOption(dns.edns.NSID, '' if v == True else v))
            if k.lower() == 'subnet':
                net = v.split('/')
                family = socket.AF_INET6 if ':' in net[0] else socket.AF_INET
                subnet_addr = net[0]
                addr = socket.inet_pton(family, net[0])
                prefix = len(addr) * 8
                if len(net) > 1:
                    prefix = int(net[1])
                addr = addr[0 : (prefix + 7)/8]
                if prefix % 8 != 0: # Mask the last byte
                    addr = addr[:-1] + chr(ord(addr[-1]) & 0xFF << (8 - prefix % 8))
                opts.append(dns.edns.GenericOption(8, struct.pack("!HBB", 1 if family == socket.AF_INET else 2, prefix, 0) + addr))
        self.message.use_edns(edns = version, payload = bufsize, options = opts)

    def begin_raw(self):
        """ Set raw data pending flag. """
        self.raw_data_pending = True

    def begin_section(self, section):
        """ Begin packet section. """
        self.section = section
        self.sections.append(section.lower())

    def add_record(self, owner, args):
        """ Add record to current packet section. """
        if self.raw_data_pending is True:
            if self.raw_data == None:
                if owner == 'NULL':
                    self.raw_data = None
                else:
                    self.raw_data = binascii.unhexlify(owner)
            else:
                raise Exception('raw data already set in this entry')
            self.raw_data_pending = False
            self.is_raw_data_entry = True
        else:
            rr = create_rr(owner, args, ttl = self.default_ttl, rdclass = self.default_cls, origin = self.origin)
            if self.section == 'QUESTION':
                if rr.rdtype == dns.rdatatype.AXFR:
                    self.message.xfr = True
                self.__rr_add(self.message.question, rr)
            elif self.section == 'ANSWER':
                self.__rr_add(self.message.answer, rr)
            elif self.section == 'AUTHORITY':
                self.__rr_add(self.message.authority, rr)
            elif self.section == 'ADDITIONAL':
                self.__rr_add(self.message.additional, rr)
            else:
                raise Exception('bad section %s' % self.section)

    def use_tsig(self,fields):
        tsig_keyname = fields[0]
        tsig_secret  = fields[1]
        keyring = dns.tsigkeyring.from_text({tsig_keyname : tsig_secret})
        self.message.use_tsig(keyring=keyring,keyname=tsig_keyname)

    def __rr_add(self, section, rr):
    	""" Merge record to existing RRSet, or append to given section. """

        if rr.rdtype != dns.rdatatype.SOA:
            for existing_rr in section:
                if existing_rr.match(rr.name, rr.rdclass, rr.rdtype, rr.covers):
                    existing_rr += rr
                    return

        section.append(rr)

    def set_mandatory(self):
        self.mandatory = True

class Range:
    """
    Range represents a set of scripted queries valid for given step range.
    """

    def __init__(self, a, b):
        """ Initialize reply range. """
        self.a = a
        self.b = b
        self.addresses = set()
        self.stored = []
        self.args = {}
        self.received = 0
        self.sent = 0

    def __del__(self):
        dtag = '[ RANGE %d-%d ] %s' % (self.a, self.b, self.addresses)
        dprint(dtag, 'received: %d sent: %d' % (self.received, self.sent))

    def add(self, entry):
        """ Append a scripted response to the range"""
        self.stored.append(entry)

    def eligible(self, id, address):
        """ Return true if this range is eligible for fetching reply. """
        if self.a <= id <= self.b:
            return (None == address
                    or set() == self.addresses
                    or address in self.addresses)
        return False

    def reply(self, query):
        """ Find matching response to given query. """
        self.received += 1
        for candidate in self.stored:
            try:
                candidate.match(query)
                resp = candidate.adjust_reply(query)
                # Probabilistic loss
                if 'LOSS' in self.args:
                    if random.random() < float(self.args['LOSS']):
                        return None
                self.sent += 1
                candidate.fired += 1
                return resp
            except Exception as e:
                pass
        return None


class Step:
    """
    Step represents one scripted action in a given moment,
    each step has an order identifier, type and optionally data entry.
    """

    require_data = ['QUERY', 'CHECK_ANSWER', 'REPLY']

    def __init__(self, id, type, extra_args):
        """ Initialize single scenario step. """
        self.id = int(id)
        self.type = type
        self.args = extra_args
        self.data = []
        self.has_data = self.type in Step.require_data
        self.answer = None
        self.raw_answer = None
        self.repeat_if_fail = 0
        self.pause_if_fail = 0
        self.next_if_fail = -1
        
        if type == 'CHECK_ANSWER':
            for arg in extra_args:
                param = arg.split('=')
                try:
                    if param[0] == 'REPEAT':
                        self.repeat_if_fail = int(param[1])
                    elif param[0] == 'PAUSE':
                        self.pause_if_fail = float(param[1])
                    elif param[0] == 'NEXT':
                        self.next_if_fail = int(param[1])
                except Exception as e:
                    raise Exception('step %d - wrong %s arg: %s' % (self.id, param[0], str(e)))


    def add(self, entry):
        """ Append a data entry to this step. """
        self.data.append(entry)

    def play(self, ctx):
        """ Play one step from a scenario. """
        dtag = '[ STEP %03d ] %s' % (self.id, self.type)
        if self.type == 'QUERY':
            dprint(dtag, self.data[0].message.to_text())
            # Parse QUERY-specific parameters
            choice, tcp, source = None, False, None
            for v in self.args:
                if '=' in v: # Key=Value
                    v = v.split('=')
                    if v[0].lower() == 'source':
                        source = v[1]
                elif v.lower() == 'tcp':
                    tcp = True
                else:
                    choice = v
            return self.__query(ctx, tcp = tcp, choice = choice, source = source)
        elif self.type == 'CHECK_OUT_QUERY':
            dprint(dtag, '')
            pass # Ignore
        elif self.type == 'CHECK_ANSWER' or self.type == 'ANSWER':
            dprint(dtag, '')
            return self.__check_answer(ctx)
        elif self.type == 'TIME_PASSES':
            dprint(dtag, '')
            return self.__time_passes(ctx)
        elif self.type == 'REPLY' or self.type == 'MOCK':
            dprint(dtag, '')
            pass
        elif self.type == 'LOG':
            if not ctx.log:
                raise Exception('scenario has no log interface')
            return ctx.log.match(self.args)
        elif self.type == 'REPLAY':
            self.__replay(ctx)
        elif self.type == 'ASSERT':
            self.__assert(ctx)
        else:
            raise Exception('step %03d type %s unsupported' % (self.id, self.type))

    def __check_answer(self, ctx):
        """ Compare answer from previously resolved query. """
        if len(self.data) == 0:
            raise Exception("response definition required")
        expected = self.data[0]
        if expected.is_raw_data_entry is True:
            dprint("", ctx.last_raw_answer.to_text())
            expected.cmp_raw(ctx.last_raw_answer)
        else:
            if ctx.last_answer is None:
                raise Exception("no answer from preceding query")
            dprint("", ctx.last_answer.to_text())
            expected.match(ctx.last_answer)

    def __replay(self, ctx, chunksize = 8):
        dtag = '[ STEP %03d ] %s' % (self.id, self.type)
        nqueries = len(self.queries)
        if len(self.args) > 0 and self.args[0].isdigit():
            nqueries = int(self.args.pop(0))
        destination = ctx.client[ctx.client.keys()[0]]
        dprint(dtag, 'replaying %d queries to %s@%d (%s)' % (nqueries, destination[0], destination[1], ' '.join(self.args)))
        if 'INTENSIFY' in os.environ:
            nqueries *= int(os.environ['INTENSIFY'])
        tstart = datetime.now()
        nsent, nrcvd = replay_rrs(self.queries, nqueries, destination, self.args)
        # Keep/print the statistics
        rtt = (datetime.now() - tstart).total_seconds() * 1000
        pps = 1000 * nrcvd / rtt
        dprint(dtag, 'sent: %d, received: %d (%d ms, %d p/s)' % (nsent, nrcvd, rtt, pps))
        tag = None
        for arg in self.args:
            if arg.upper().startswith('PRINT'):
                _, tag = tuple(arg.split('=')) if '=' in arg else (None, 'replay')
        if tag:
            print('  [ REPLAY ] test: %s pps: %5d time: %4d sent: %5d received: %5d' % (tag.ljust(11), pps, rtt, nsent, nrcvd))


    def __query(self, ctx, tcp = False, choice = None, source = None):
        """ Resolve a query. """
        if len(self.data) == 0:
            raise Exception("query definition required")
        if self.data[0].is_raw_data_entry is True:
            data_to_wire = self.data[0].raw_data
        else:
            # Don't use a message copy as the EDNS data portion is not copied.
            data_to_wire = self.data[0].message.to_wire()
        if choice is None or len(choice) == 0:
            choice = ctx.client.keys()[0]
        if choice not in ctx.client:
            raise Exception('step %03d invalid QUERY target: %s' % (self.id, choice))
        # Create socket to test subject
        sock = None
        destination = ctx.client[choice]
        family = socket.AF_INET6 if ':' in destination[0] else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if tcp:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        sock.settimeout(3)
        if source:
            sock.bind((source, 0))    
        sock.connect(destination)
        # Send query to client and wait for response
        tstart = datetime.now()
        log_packet(sock, data_to_wire, query = True)
        while True:
            try:
                sendto_msg(sock, data_to_wire)
                break
            except OSError, e:
                # ENOBUFS, throttle sending
                if e.errno == errno.ENOBUFS:
                    time.sleep(0.1)
        # Wait for a response for a reasonable time
        answer = None
        if not self.data[0].is_raw_data_entry:
            while True:
                try:
                    answer, _ = recvfrom_msg(sock, True)
                    break
                except OSError, e:
                    if e.errno == errno.ENOBUFS:
                        time.sleep(0.1)
        # Track RTT
        rtt = (datetime.now() - tstart).total_seconds() * 1000
        global g_rtt, g_nqueries
        g_nqueries += 1
        g_rtt += rtt
        # Remember last answer for checking later
        self.raw_answer = answer
        ctx.last_raw_answer = answer
        if self.raw_answer is not None:
            self.answer = dns.message.from_wire(self.raw_answer)
            log_packet(sock, answer, query = False)
        else:
            self.answer = None
        ctx.last_answer = self.answer

    def __time_passes(self, ctx):
        """ Modify system time. """
        time_file = open(os.environ["FAKETIME_TIMESTAMP_FILE"], 'r')
        line = time_file.readline().strip()
        time_file.close()
        t = time.mktime(datetime.strptime(line, '@%Y-%m-%d %H:%M:%S').timetuple())
        t += int(self.args[1])
        time_file = open(os.environ["FAKETIME_TIMESTAMP_FILE"], 'w')
        time_file.write(datetime.fromtimestamp(t).strftime('@%Y-%m-%d %H:%M:%S') + "\n")
        time_file.flush()
        time_file.close()

    def __assert(self, ctx):
        """ Assert that a passed expression evaluates to True. """
        result = eval(' '.join(self.args), {'SCENARIO': ctx, 'RANGE': ctx.ranges})
        # Evaluate subexpressions for clarity
        subexpr = []
        for expr in self.args:
            try:
                ee = eval(expr, {'SCENARIO': ctx, 'RANGE': ctx.ranges})
                subexpr.append(str(ee))
            except:
                subexpr.append(expr)
        assert result is True, '"%s" assertion fails (%s)' % (' '.join(self.args), ' '.join(subexpr))

class Scenario:
    def __init__(self, info, filename = ''):
        """ Initialize scenario with description. """
        self.info = info
        self.file = filename
        self.ranges = []
        self.current_range = None
        self.steps = []
        self.current_step = None
        self.client = {}
        self.force_ipv6 = False

    def reply(self, query, address = None):
        """ Attempt to find a range reply for a query. """
        step_id = 0
        if self.current_step is not None:
            step_id = self.current_step.id
        # Unknown address, select any match
        # TODO: workaround until the server supports stub zones
        all_addresses = set()
        for rng in self.ranges:
            all_addresses.update(rng.addresses)
        if address not in all_addresses:
            address = None
        # Find current valid query response range
        for rng in self.ranges:
            if rng.eligible(step_id, address):
                self.current_range = rng
                return (rng.reply(query), False)
        # Find any prescripted one-shot replies
        for step in self.steps:
            if step.id < step_id or step.type != 'REPLY':
                continue
            try:
                candidate = step.data[0]
                if candidate.is_raw_data_entry is False:
                    candidate.match(query)
                    step.data.remove(candidate)
                    answer = candidate.adjust_reply(query)
                    return (answer, False)
                else:
                    answer = candidate.raw_data
                    return (answer, True)
            except:
                pass
        return (None, True)

    def play(self, family, paddr):
        """ Play given scenario. """
        # Store test subject => address mapping
        self.client = paddr

        step = None
        i = 0
        while i < len(self.steps):
            step = self.steps[i]
            self.current_step = step
            try:
                step.play(self)
            except Exception as e:
                if (step.repeat_if_fail > 0):
                    dprint ('[play]',"step %d: exception catched - '%s', retrying step %d (%d left)" % (step.id, e, step.next_if_fail, step.repeat_if_fail))
                    step.repeat_if_fail -= 1
                    if (step.pause_if_fail > 0):
                        time.sleep(step.pause_if_fail)
                    if (step.next_if_fail != -1):
                        next_steps = [j for j in range(len(self.steps)) if self.steps[j].id == step.next_if_fail]
                        if (len(next_steps) == 0):
                            raise Exception('step %d: wrong NEXT value "%d"' % (step.id, step.next_if_fail))
                        next_step = next_steps[0]
                        if (next_step < len(self.steps)):
                            i = next_step
                        else:
                            raise Exception('step %d: Can''t branch to NEXT value "%d"' % (step.id, step.next_if_fail))
                    continue
                else:
                    raise Exception('%s step %d %s' % (self.file, step.id, str(e)))
            i = i + 1

        for r in self.ranges:
            for e in r.stored:
                if e.mandatory is True and e.fired == 0:
                    raise Exception('Mandatory section at line %d is not fired' % e.lineno)


def get_next(file_in, skip_empty = True):
    """ Return next token from the input stream. """
    while True:
        line = file_in.readline()
        if len(line) == 0:
            return False
        quoted, escaped = False, False
        for i in range(len(line)):
            if line[i] == '\\':
                escaped = not escaped
            if not escaped and line[i] == '"':
                quoted = not quoted
            if line[i] in (';') and not quoted:
                line = line[0:i]
                break
            if line[i] != '\\':
                escaped = False
        tokens = ' '.join(line.strip().split()).split()
        if len(tokens) == 0:
            if skip_empty:
                continue
            else:
                return '', []
        op = tokens.pop(0)
        return op, tokens

def parse_entry(op, args, file_in, in_entry = False):
    """ Parse entry definition. """
    out = Entry(file_in.lineno())
    for op, args in iter(lambda: get_next(file_in, in_entry), False):
        if op == 'ENTRY_END' or op == '':
            in_entry = False
            break
        elif op == 'ENTRY_BEGIN': # Optional, compatibility with Unbound tests
            if in_entry:
                raise Exception('nested ENTRY_BEGIN not supported')
            in_entry = True
            pass
        elif op == 'EDNS':
            out.set_edns(args)
        elif op == 'REPLY' or op == 'FLAGS':
            out.set_reply(args)
        elif op == 'MATCH':
            out.set_match(args)
        elif op == 'ADJUST':
            out.set_adjust(args)
        elif op == 'SECTION':
            out.begin_section(args[0])
        elif op == 'RAW':
            out.begin_raw()
        elif op == 'TSIG':
            out.use_tsig(args)
        elif op == 'MANDATORY':
            out.set_mandatory()
        else:
            out.add_record(op, args)
    return out

def parse_queries(out, file_in):
    """ Parse list of queries terminated by blank line. """
    out.queries = []
    for op, args in iter(lambda: get_next(file_in, False), False):
        if op == '':
            break
        out.queries.append(create_rr(op, args))
    return out

auto_step = 0
def parse_step(op, args, file_in):
    """ Parse range definition. """
    global auto_step
    if len(args) == 0:
        raise Exception('expected at least STEP <type>')
    # Auto-increment when step ID isn't specified
    if len(args) < 2 or not args[0].isdigit():
        args = [str(auto_step)] + args
    auto_step = int(args[0]) + 1
    out = Step(args[0], args[1], args[2:])
    if out.has_data:
        out.add(parse_entry(op, args, file_in))
    # Special steps
    if args[1] == 'REPLAY':
        parse_queries(out, file_in)
    return out


def parse_range(op, args, file_in):
    """ Parse range definition. """
    if len(args) < 2:
        raise Exception('expected RANGE_BEGIN <from> <to> [address]')
    out = Range(int(args[0]), int(args[1]))
    # Shortcut for address
    if len(args) > 2:
        out.addresses.add(args[2])
    # Parameters
    if len(args) > 3:
        out.args = {}
        for v in args[3:]:
            k, v = tuple(v.split('=')) if '=' in v else (v, True)
            out.args[k] = v
    for op, args in iter(lambda: get_next(file_in), False):
        if op == 'ADDRESS':
            out.addresses.add(args[0])
        elif op == 'ENTRY_BEGIN':
            out.add(parse_entry(op, args, file_in, in_entry = True))
        elif op == 'RANGE_END':
            break
    return out


def parse_scenario(op, args, file_in):
    """ Parse scenario definition. """
    out = Scenario(args[0], file_in.filename())
    for op, args in iter(lambda: get_next(file_in), False):
        if op == 'SCENARIO_END':
            break
        if op == 'RANGE_BEGIN':
            out.ranges.append(parse_range(op, args, file_in))
        if op == 'STEP':
            out.steps.append(parse_step(op, args, file_in))
    return out


def parse_file(file_in):
    """ Parse scenario from a file. """
    try:
        config = []
        line = file_in.readline()
        while len(line):
            # Zero-configuration
            if line.startswith('SCENARIO_BEGIN'):
                return parse_scenario(line, line.split(' ')[1:], file_in), config
            if line.startswith('CONFIG_END'):
                break
            if not line.startswith(';'):
                if '#' in line:
                    line = line[0:line.index('#')]
                # Break to key-value pairs
                # e.g.: ['minimization', 'on']
                kv = [x.strip() for x in line.split(':',1)]
                if len(kv) >= 2:
                    config.append(kv)
            line = file_in.readline()

        for op, args in iter(lambda: get_next(file_in), False):
            if op == 'SCENARIO_BEGIN':
                return parse_scenario(op, args, file_in), config
        raise Exception("IGNORE (missing scenario)")
    except Exception as e:
        raise Exception('%s#%d: %s' % (file_in.filename(), file_in.lineno(), str(e)))
