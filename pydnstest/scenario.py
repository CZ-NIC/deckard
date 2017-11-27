from __future__ import absolute_import

import binascii
import calendar
import errno
import logging
import os
import posixpath
import random
import socket
import string
import struct
import time
from datetime import datetime

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rrset
import dns.tsigkeyring

import pydnstest.augwrap


def str2bool(v):
    """ Return conversion of JSON-ish string value to boolean. """
    return v.lower() in ('yes', 'true', 'on', '1')


# Global statistics
g_rtt = 0.0
g_nqueries = 0

#
# Element comparators
#


def compare_rrs(expected, got):
    """ Compare lists of RR sets, throw exception if different. """
    for rr in expected:
        if rr not in got:
            raise ValueError("expected record '%s'" % rr.to_text())
    for rr in got:
        if rr not in expected:
            raise ValueError("unexpected record '%s'" % rr.to_text())
    if len(expected) != len(got):
        raise ValueError("expected %s records but got %s records "
                         "(a duplicate RR somewhere?)"
                         % (len(expected), len(got)))
    return True


def compare_val(expected, got):
    """ Compare values, throw exception if different. """
    if expected != got:
        raise ValueError("expected '%s', got '%s'" % (expected, got))
    return True


def compare_sub(got, expected):
    """ Check if got subdomain of expected, throw exception if different. """
    if not expected.is_subdomain(got):
        raise ValueError("expected subdomain of '%s', got '%s'" % (expected, got))
    return True


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


def sendto_msg(stream, message, addr=None):
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
    except socket.error as ex:
        if ex.errno != errno.ECONNREFUSED:  # TODO Investigate how this can happen
            raise


def replay_rrs(rrs, nqueries, destination, args=[]):
    """ Replay list of queries and report statistics. """
    navail, queries = len(rrs), []
    chunksize = 16
    for i in range(nqueries if 'RAND' in args else navail):
        rr = rrs[i % navail]
        name = rr.name
        if 'RAND' in args:
            prefix = ''.join([random.choice(string.ascii_letters + string.digits)
                              for _ in range(8)])
            name = prefix + '.' + rr.name.to_text()
        msg = dns.message.make_query(name, rr.rdtype, rr.rdclass)
        if 'DO' in args:
            msg.want_dnssec(True)
        queries.append(msg.to_wire())
    # Make a UDP connected socket to the destination
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
        if to_write:
            try:
                while nsent < nqueries and nwait < chunksize:
                    sock.send(queries[nsent % navail])
                    nwait += 1
                    nsent += 1
            except socket.error:
                pass  # EINVAL
        if to_read:
            try:
                while nwait > 0:
                    sock.recv_into(rcvbuf)
                    nwait -= 1
                    nrcvd += 1
            except socket.error:
                pass
        if not to_write and not to_read:
            nwait = 0  # Timeout, started dropping packets
            break
    return nsent, nrcvd


class Entry:
    """
    Data entry represents scripted message and extra metadata,
    notably match criteria and reply adjustments.
    """

    # Globals
    default_ttl = 3600
    default_cls = 'IN'
    default_rc = 'NOERROR'

    def __init__(self, node):
        """ Initialize data entry. """
        self.node = node
        self.origin = '.'
        self.message = dns.message.Message()
        self.message.use_edns(edns=0, payload=4096)
        self.fired = 0

        # RAW
        try:
            self.raw_data = binascii.unhexlify(node["/raw"].value)
            self.is_raw_data_entry = True
            return
        except KeyError:
            self.raw_data = None
            self.is_raw_data_entry = False

        # MATCH
        self.match_fields = [m.value for m in node.match("/match")]

        if not self.match_fields:
            self.match_fields = ['opcode', 'qtype', 'qname']

        # FLAGS
        self.process_reply_line(node)

        # ADJUST
        self.adjust_fields = [m.value for m in node.match("/adjust")]
        if not self.adjust_fields:
            self.adjust_fields = ['copy_id']

        # MANDATORY
        try:
            self.mandatory = list(node.match("/mandatory"))[0]
        except (KeyError, IndexError):
            self.mandatory = None

        # TSIG
        try:
            tsig = list(node.match("/tsig"))[0]
            tsig_keyname = tsig["/keyname"].value
            tsig_secret = tsig["/secret"].value
            keyring = dns.tsigkeyring.from_text({tsig_keyname: tsig_secret})
            self.message.use_tsig(keyring=keyring, keyname=tsig_keyname)
        except (KeyError, IndexError):
            pass

        # SECTIONS & RECORDS
        self.sections = []
        for section in node.match("/section/*"):
            section_name = posixpath.basename(section.path)
            self.sections.append(section_name)
            for record in section.match("/record"):
                owner = record['/domain'].value
                if not owner.endswith("."):
                    owner += self.origin
                try:
                    ttl = dns.ttl.from_text(record['/ttl'].value)
                except KeyError:
                    ttl = self.default_ttl
                try:
                    rdclass = dns.rdataclass.from_text(record['/class'].value)
                except KeyError:
                    rdclass = dns.rdataclass.from_text(self.default_cls)
                rdtype = dns.rdatatype.from_text(record['/type'].value)
                rr = dns.rrset.from_text(owner, ttl, rdclass, rdtype)
                if section_name != "question":
                    rd = record['/data'].value.split()
                    if rd:
                        if rdtype == dns.rdatatype.DS:
                            rd[1] = str(dns.dnssec.algorithm_from_text(rd[1]))
                        rd = dns.rdata.from_text(rr.rdclass, rr.rdtype, ' '.join(
                            rd), origin=dns.name.from_text(self.origin), relativize=False)
                    rr.add(rd)
                if section_name == 'question':
                    if rr.rdtype == dns.rdatatype.AXFR:
                        self.message.xfr = True
                    self.message.question.append(rr)
                elif section_name == 'answer':
                    self.message.answer.append(rr)
                elif section_name == 'authority':
                    self.message.authority.append(rr)
                elif section_name == 'additional':
                    self.message.additional.append(rr)

    def __str__(self):
        txt = 'ENTRY_BEGIN\n'
        if not self.is_raw_data_entry:
            txt += 'MATCH {0}\n'.format(' '.join(self.match_fields))
        txt += 'ADJUST {0}\n'.format(' '.join(self.adjust_fields))
        txt += 'REPLY {rcode} {flags}\n'.format(
            rcode=dns.rcode.to_text(self.message.rcode()),
            flags=' '.join([dns.flags.to_text(self.message.flags),
                            dns.flags.edns_to_text(self.message.ednsflags)])
        )
        for sect_name in ['question', 'answer', 'authority', 'additional']:
            sect = getattr(self.message, sect_name)
            if not sect:
                continue
            txt += 'SECTION {n}\n'.format(n=sect_name.upper())
            for rr in sect:
                txt += str(rr)
                txt += '\n'
        if self.is_raw_data_entry:
            txt += 'RAW\n'
            if self.raw_data:
                txt += binascii.hexlify(self.raw_data)
            else:
                txt += 'NULL'
            txt += '\n'
        txt += 'ENTRY_END\n'
        return txt

    def process_reply_line(self, node):
        """Extracts flags, rcode and opcode from given node and adjust dns message accordingly"""
        self.fields = [f.value for f in node.match("/reply")]
        if 'DO' in self.fields:
            self.message.want_dnssec(True)
        opcode = self.get_opcode(fields=self.fields)
        rcode = self.get_rcode(fields=self.fields)
        self.message.flags = self.get_flags(fields=self.fields)
        if rcode is not None:
            self.message.set_rcode(rcode)
        if opcode is not None:
            self.message.set_opcode(opcode)

    @classmethod
    def get_flags(cls, fields):
        """From `fields` extracts and returns flags"""
        flags = []
        for code in fields:
            try:
                dns.flags.from_text(code)  # throws KeyError on failure
                flags.append(code)
            except KeyError:
                pass
        return dns.flags.from_text(' '.join(flags))

    @classmethod
    def get_rcode(cls, fields):
        """
        From `fields` extracts and returns rcode.
        Throws `ValueError` if there are more then one rcodes
        """
        rcodes = []
        for code in fields:
            try:
                rcodes.append(dns.rcode.from_text(code))
            except dns.rcode.UnknownRcode:
                pass
        if len(rcodes) > 1:
            raise ValueError("Parse failed, too many rcode values.", rcodes)
        if len(rcodes) == 0:
            return None
        return rcodes[0]

    @classmethod
    def get_opcode(cls, fields):
        """
        From `fields` extracts and returns opcode.
        Throws `ValueError` if there are more then one opcodes
        """
        opcodes = []
        for code in fields:
            try:
                opcodes.append(dns.opcode.from_text(code))
            except dns.opcode.UnknownOpcode:
                pass
        if len(opcodes) > 1:
            raise ValueError("Parse failed, too many opcode values.")
        if len(opcodes) == 0:
            return None
        return opcodes[0]

    def match_part(self, code, msg):
        """ Compare scripted reply to given message using single criteria. """
        if code not in self.match_fields and 'all' not in self.match_fields:
            return True
        expected = self.message
        if code == 'opcode':
            return compare_val(expected.opcode(), msg.opcode())
        elif code == 'qtype':
            if not expected.question:
                return True
            return compare_val(expected.question[0].rdtype, msg.question[0].rdtype)
        elif code == 'qname':
            if not expected.question:
                return True
            qname = dns.name.from_text(msg.question[0].name.to_text().lower())
            return compare_val(expected.question[0].name, qname)
        elif code == 'qcase':
            return compare_val(msg.question[0].name.labels, expected.question[0].name.labels)
        elif code == 'subdomain':
            if not expected.question:
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
                raise ValueError('expected EDNS %d, got %d' % (expected.edns, msg.edns))
            if msg.payload != expected.payload:
                raise ValueError('expected EDNS bufsize %d, got %d'
                                 % (expected.payload, msg.payload))
        elif code == 'nsid':
            nsid_opt = None
            for opt in expected.options:
                if opt.otype == dns.edns.NSID:
                    nsid_opt = opt
                    break
            # Find matching NSID
            for opt in msg.options:
                if opt.otype == dns.edns.NSID:
                    if not nsid_opt:
                        raise ValueError('unexpected NSID value "%s"' % opt.data)
                    if opt == nsid_opt:
                        return True
                    else:
                        raise ValueError('expected NSID "%s", got "%s"' % (nsid_opt.data, opt.data))
            if nsid_opt:
                raise ValueError('expected NSID "%s"' % nsid_opt.data)
        else:
            raise ValueError('unknown match request "%s"' % code)

    def match(self, msg):
        """ Compare scripted reply to given message based on match criteria. """
        match_fields = self.match_fields
        if 'all' in match_fields:
            match_fields.remove('all')
            match_fields += ['flags'] + ['rcode'] + self.sections
        for code in match_fields:
            try:
                self.match_part(code, msg)
            except ValueError as ex:
                errstr = '%s in the response:\n%s' % (str(ex), msg.to_text())
                # TODO: cisla radku
                raise ValueError("%s, \"%s\": %s" % (self.node.span, code, errstr))

    def cmp_raw(self, raw_value):
        assert self.is_raw_data_entry
        expected = None
        if self.raw_data is not None:
            expected = binascii.hexlify(self.raw_data)
        got = None
        if raw_value is not None:
            got = binascii.hexlify(raw_value)
        if expected != got:
            raise ValueError("raw message comparsion failed: expected %s got %s" % (expected, got))

    def adjust_reply(self, query):
        """ Copy scripted reply and adjust to received query. """
        answer = dns.message.from_wire(self.message.to_wire(),
                                       xfr=self.message.xfr,
                                       one_rr_per_rrset=True)
        answer.use_edns(query.edns, query.ednsflags, options=self.message.options)
        if 'copy_id' in self.adjust_fields:
            answer.id = query.id
            # Copy letter-case if the template has QD
            if answer.question:
                answer.question[0].name = query.question[0].name
        if 'copy_query' in self.adjust_fields:
            answer.question = query.question
        # Re-set, as the EDNS might have reset the ext-rcode
        answer.set_rcode(self.message.rcode())

        # sanity check: adjusted answer should be almost the same
        assert len(answer.answer) == len(self.message.answer)
        assert len(answer.authority) == len(self.message.authority)
        assert len(answer.additional) == len(self.message.additional)
        return answer

    def set_edns(self, fields):
        """ Set EDNS version and bufsize. """
        version = 0
        bufsize = 4096
        if fields and fields[0].isdigit():
            version = int(fields.pop(0))
        if fields and fields[0].isdigit():
            bufsize = int(fields.pop(0))
        if bufsize == 0:
            self.message.use_edns(False)
            return
        opts = []
        for v in fields:
            k, v = tuple(v.split('=')) if '=' in v else (v, True)
            if k.lower() == 'nsid':
                opts.append(dns.edns.GenericOption(dns.edns.NSID, '' if v is True else v))
            if k.lower() == 'subnet':
                net = v.split('/')
                subnet_addr = net[0]
                family = socket.AF_INET6 if ':' in subnet_addr else socket.AF_INET
                addr = socket.inet_pton(family, subnet_addr)
                prefix = len(addr) * 8
                if len(net) > 1:
                    prefix = int(net[1])
                addr = addr[0: (prefix + 7) / 8]
                if prefix % 8 != 0:  # Mask the last byte
                    addr = addr[:-1] + chr(ord(addr[-1]) & 0xFF << (8 - prefix % 8))
                opts.append(dns.edns.GenericOption(8, struct.pack(
                    "!HBB", 1 if family == socket.AF_INET else 2, prefix, 0) + addr))
        self.message.use_edns(edns=version, payload=bufsize, options=opts)


class Range:
    """
    Range represents a set of scripted queries valid for given step range.
    """
    log = logging.getLogger('pydnstest.scenario.Range')

    def __init__(self, node):
        """ Initialize reply range. """
        self.node = node
        self.a = int(node['/from'].value)
        self.b = int(node['/to'].value)

        address = node["/address"].value
        self.addresses = {address} if address is not None else set()
        self.addresses |= set([a.value for a in node.match("/address/*")])
        self.stored = [Entry(n) for n in node.match("/entry")]
        self.args = {}
        self.received = 0
        self.sent = 0

    def __del__(self):
        self.log.info('[ RANGE %d-%d ] %s received: %d sent: %d',
                      self.a, self.b, self.addresses, self.received, self.sent)

    def __str__(self):
        txt = '\nRANGE_BEGIN {a} {b}\n'.format(a=self.a, b=self.b)
        for addr in self.addresses:
            txt += '        ADDRESS {0}\n'.format(addr)

        for entry in self.stored:
            txt += '\n'
            txt += str(entry)
        txt += 'RANGE_END\n\n'
        return txt

    def eligible(self, id, address):
        """ Return true if this range is eligible for fetching reply. """
        if self.a <= id <= self.b:
            return (None is address
                    or set() == self.addresses
                    or address in self.addresses)
        return False

    def reply(self, query):
        """
        Get answer for given query (adjusted if needed).

        Returns:
            (DNS message object) or None if there is no candidate in this range
        """
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
            except ValueError:
                pass
        return None


class StepLogger(logging.LoggerAdapter):  # pylint: disable=too-few-public-methods
    """
    Prepent Step identification before each log message.
    """
    def process(self, msg, kwargs):
        return '[STEP %s %s] %s' % (self.extra['id'], self.extra['type'], msg), kwargs


class Step:
    """
    Step represents one scripted action in a given moment,
    each step has an order identifier, type and optionally data entry.
    """
    require_data = ['QUERY', 'CHECK_ANSWER', 'REPLY']

    def __init__(self, node):
        """ Initialize single scenario step. """
        self.node = node
        self.id = int(node.value)
        self.type = node["/type"].value
        self.log = StepLogger(logging.getLogger('pydnstest.scenario.Step'),
                              {'id': self.id, 'type': self.type})
        try:
            self.delay = int(node["/timestamp"].value)
        except KeyError:
            pass
        self.data = [Entry(n) for n in node.match("/entry")]
        self.queries = []
        self.has_data = self.type in Step.require_data
        self.answer = None
        self.raw_answer = None
        self.repeat_if_fail = 0
        self.pause_if_fail = 0
        self.next_if_fail = -1

        # TODO Parser currently can't parse CHECK_ANSWER args, player doesn't understand them anyway
        # if type == 'CHECK_ANSWER':
        #     for arg in extra_args:
        #         param = arg.split('=')
        #         try:
        #             if param[0] == 'REPEAT':
        #                 self.repeat_if_fail = int(param[1])
        #             elif param[0] == 'PAUSE':
        #                 self.pause_if_fail = float(param[1])
        #             elif param[0] == 'NEXT':
        #                 self.next_if_fail = int(param[1])
        #         except Exception as e:
        #             raise Exception('step %d - wrong %s arg: %s' % (self.id, param[0], str(e)))

    def __str__(self):
        txt = '\nSTEP {i} {t}'.format(i=self.id, t=self.type)
        if self.repeat_if_fail:
            txt += ' REPEAT {v}'.format(v=self.repeat_if_fail)
        elif self.pause_if_fail:
            txt += ' PAUSE {v}'.format(v=self.pause_if_fail)
        elif self.next_if_fail != -1:
            txt += ' NEXT {v}'.format(v=self.next_if_fail)
        # if self.args:
        #     txt += ' '
        #     txt += ' '.join(self.args)
        txt += '\n'

        for data in self.data:
            # from IPython.core.debugger import Tracer
            # Tracer()()
            txt += str(data)
        return txt

    def play(self, ctx):
        """ Play one step from a scenario. """
        if self.type == 'QUERY':
            self.log.info('')
            self.log.debug(self.data[0].message.to_text())
            # Parse QUERY-specific parameters
            choice, tcp, source = None, False, None
            return self.__query(ctx, tcp=tcp, choice=choice, source=source)
        elif self.type == 'CHECK_OUT_QUERY':
            self.log.info('')
            pass  # Ignore
        elif self.type == 'CHECK_ANSWER' or self.type == 'ANSWER':
            self.log.info('')
            return self.__check_answer(ctx)
        elif self.type == 'TIME_PASSES ELAPSE':
            self.log.info('')
            return self.__time_passes()
        elif self.type == 'REPLY' or self.type == 'MOCK':
            self.log.info('')
        # Parser currently doesn't support step types LOG, REPLAY and ASSERT.
        # No test uses them.
        # elif self.type == 'LOG':
        #     if not ctx.log:
        #         raise Exception('scenario has no log interface')
        #     return ctx.log.match(self.args)
        # elif self.type == 'REPLAY':
        #     self.__replay(ctx)
        # elif self.type == 'ASSERT':
        #     self.__assert(ctx)
        else:
            raise NotImplementedError('step %03d type %s unsupported' % (self.id, self.type))

    def __check_answer(self, ctx):
        """ Compare answer from previously resolved query. """
        if not self.data:
            raise ValueError("response definition required")
        expected = self.data[0]
        if expected.is_raw_data_entry is True:
            self.log.debug("raw answer: %s", ctx.last_raw_answer.to_text())
            expected.cmp_raw(ctx.last_raw_answer)
        else:
            if ctx.last_answer is None:
                raise ValueError("no answer from preceding query")
            self.log.debug("answer: %s", ctx.last_answer.to_text())
            expected.match(ctx.last_answer)

    # def __replay(self, ctx, chunksize=8):
    #     nqueries = len(self.queries)
    #     if len(self.args) > 0 and self.args[0].isdigit():
    #         nqueries = int(self.args.pop(0))
    #     destination = ctx.client[ctx.client.keys()[0]]
    #     self.log.info('replaying %d queries to %s@%d (%s)',
    #                   nqueries, destination[0], destination[1], ' '.join(self.args))
    #     if 'INTENSIFY' in os.environ:
    #         nqueries *= int(os.environ['INTENSIFY'])
    #     tstart = datetime.now()
    #     nsent, nrcvd = replay_rrs(self.queries, nqueries, destination, self.args)
    #     # Keep/print the statistics
    #     rtt = (datetime.now() - tstart).total_seconds() * 1000
    #     pps = 1000 * nrcvd / rtt
    #     self.log.debug('sent: %d, received: %d (%d ms, %d p/s)', nsent, nrcvd, rtt, pps)
    #     tag = None
    #     for arg in self.args:
    #         if arg.upper().startswith('PRINT'):
    #             _, tag = tuple(arg.split('=')) if '=' in arg else (None, 'replay')
    #     if tag:
    #         self.log.info('[ REPLAY ] test: %s pps: %5d time: %4d sent: %5d received: %5d',
    #                       tag.ljust(11), pps, rtt, nsent, nrcvd)

    def __query(self, ctx, tcp=False, choice=None, source=None):
        """
        Send query and wait for an answer (if the query is not RAW).

        The received answer is stored in self.answer and ctx.last_answer.
        """
        if not self.data:
            raise ValueError("query definition required")
        if self.data[0].is_raw_data_entry is True:
            data_to_wire = self.data[0].raw_data
        else:
            # Don't use a message copy as the EDNS data portion is not copied.
            data_to_wire = self.data[0].message.to_wire()
        if choice is None or not choice:
            choice = list(ctx.client.keys())[0]
        if choice not in ctx.client:
            raise ValueError('step %03d invalid QUERY target: %s' % (self.id, choice))
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
        while True:
            try:
                sendto_msg(sock, data_to_wire)
                break
            except OSError as ex:
                # ENOBUFS, throttle sending
                if ex.errno == errno.ENOBUFS:
                    time.sleep(0.1)
        # Wait for a response for a reasonable time
        answer = None
        if not self.data[0].is_raw_data_entry:
            while True:
                try:
                    answer, _ = recvfrom_msg(sock, True)
                    break
                except OSError as ex:
                    if ex.errno == errno.ENOBUFS:
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
            self.answer = dns.message.from_wire(self.raw_answer, one_rr_per_rrset=True)
        else:
            self.answer = None
        ctx.last_answer = self.answer

    def __time_passes(self):
        """ Modify system time. """
        file_old = os.environ["FAKETIME_TIMESTAMP_FILE"]
        file_next = os.environ["FAKETIME_TIMESTAMP_FILE"] + ".next"
        with open(file_old, 'r') as time_file:
            line = time_file.readline().strip()
        t = time.mktime(datetime.strptime(line, '@%Y-%m-%d %H:%M:%S').timetuple())
        t += self.delay
        with open(file_next, 'w') as time_file:
            time_file.write(datetime.fromtimestamp(t).strftime('@%Y-%m-%d %H:%M:%S') + "\n")
            time_file.flush()
        os.replace(file_next, file_old)

    # def __assert(self, ctx):
    #     """ Assert that a passed expression evaluates to True. """
    #     result = eval(' '.join(self.args), {'SCENARIO': ctx, 'RANGE': ctx.ranges})
    #     # Evaluate subexpressions for clarity
    #     subexpr = []
    #     for expr in self.args:
    #         try:
    #             ee = eval(expr, {'SCENARIO': ctx, 'RANGE': ctx.ranges})
    #             subexpr.append(str(ee))
    #         except:
    #             subexpr.append(expr)
    #     assert result is True, '"%s" assertion fails (%s)' % (
    #                            ' '.join(self.args), ' '.join(subexpr))


class Scenario:
    log = logging.getLogger('pydnstest.scenatio.Scenario')

    def __init__(self, node, filename):
        """ Initialize scenario with description. """
        self.node = node
        self.info = node.value
        self.file = filename
        self.ranges = [Range(n) for n in node.match("/range")]
        self.current_range = None
        self.steps = [Step(n) for n in node.match("/step")]
        self.current_step = None
        self.client = {}

    def __str__(self):
        txt = 'SCENARIO_BEGIN'
        if self.info:
            txt += ' {0}'.format(self.info)
        txt += '\n'
        for range in self.ranges:
            txt += str(range)
        for step in self.steps:
            txt += str(step)
        txt += "\nSCENARIO_END"
        return txt

    def reply(self, query, address=None):
        """
        Generate answer packet for given query.

        The answer can be DNS message object or a binary blob.
        Returns:
            (answer, boolean "is the answer binary blob?")
        """
        current_step_id = self.current_step.id
        # Unknown address, select any match
        # TODO: workaround until the server supports stub zones
        all_addresses = set()
        for rng in self.ranges:
            all_addresses.update(rng.addresses)
        if address not in all_addresses:
            address = None
        # Find current valid query response range
        for rng in self.ranges:
            if rng.eligible(current_step_id, address):
                self.current_range = rng
                return rng.reply(query), False
        # Find any prescripted one-shot replies
        for step in self.steps:
            if step.id < current_step_id or step.type != 'REPLY':
                continue
            try:
                candidate = step.data[0]
                if candidate.is_raw_data_entry is False:
                    candidate.match(query)
                    step.data.remove(candidate)
                    answer = candidate.adjust_reply(query)
                    return answer, False
                else:
                    answer = candidate.raw_data
                    return answer, True
            except (IndexError, ValueError):
                pass
        return None, True

    def play(self, paddr):
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
            except ValueError as ex:
                if step.repeat_if_fail > 0:
                    self.log.info("[play] step %d: exception - '%s', retrying step %d (%d left)",
                                  step.id, ex, step.next_if_fail, step.repeat_if_fail)
                    step.repeat_if_fail -= 1
                    if step.pause_if_fail > 0:
                        time.sleep(step.pause_if_fail)
                    if step.next_if_fail != -1:
                        next_steps = [j for j in range(len(self.steps)) if self.steps[
                            j].id == step.next_if_fail]
                        if not next_steps:
                            raise ValueError('step %d: wrong NEXT value "%d"' %
                                             (step.id, step.next_if_fail))
                        next_step = next_steps[0]
                        if next_step < len(self.steps):
                            i = next_step
                        else:
                            raise ValueError('step %d: Can''t branch to NEXT value "%d"' %
                                             (step.id, step.next_if_fail))
                    continue
                else:
                    raise ValueError('%s step %d %s' % (self.file, step.id, str(ex)))
            i += 1

        for r in self.ranges:
            for e in r.stored:
                if e.mandatory and e.fired == 0:
                    # TODO: cisla radku
                    raise RuntimeError('Mandatory section at %s not fired' % e.mandatory.span)


def get_next(file_in, skip_empty=True):
    """ Return next token from the input stream. """
    while True:
        line = file_in.readline()
        if not line:
            return False
        quoted, escaped = False, False
        for i in range(len(line)):
            if line[i] == '\\':
                escaped = not escaped
            if not escaped and line[i] == '"':
                quoted = not quoted
            if line[i] in ';' and not quoted:
                line = line[0:i]
                break
            if line[i] != '\\':
                escaped = False
        tokens = ' '.join(line.strip().split()).split()
        if not tokens:
            if skip_empty:
                continue
            else:
                return '', []
        op = tokens.pop(0)
        return op, tokens


def parse_config(scn_cfg, qmin, installdir):
    """
    Transform scene config (key, value) pairs into dict filled with defaults.
    Returns tuple:
      context dict: {Jinja2 variable: value}
      trust anchor dict: {domain: [TA lines for particular domain]}
    """
    # defaults
    do_not_query_localhost = True
    harden_glue = True
    sockfamily = 0  # auto-select value for socket.getaddrinfo
    trust_anchor_list = []
    trust_anchor_files = {}
    stub_addr = None
    override_timestamp = None

    features = {}
    feature_list_delimiter = ';'
    feature_pair_delimiter = '='

    for k, v in scn_cfg:
        # Enable selectively for some tests
        if k == 'do-not-query-localhost':
            do_not_query_localhost = str2bool(v)
        if k == 'harden-glue':
            harden_glue = str2bool(v)
        if k == 'query-minimization':
            qmin = str2bool(v)
        elif k == 'trust-anchor':
            trust_anchor = v.strip('"\'')
            trust_anchor_list.append(trust_anchor)
            domain = dns.name.from_text(trust_anchor.split()[0]).canonicalize()
            if domain not in trust_anchor_files:
                trust_anchor_files[domain] = []
            trust_anchor_files[domain].append(trust_anchor)
        elif k == 'val-override-timestamp':
            override_timestamp_str = v.strip('"\'')
            override_timestamp = int(override_timestamp_str)
        elif k == 'val-override-date':
            override_date_str = v.strip('"\'')
            ovr_yr = override_date_str[0:4]
            ovr_mnt = override_date_str[4:6]
            ovr_day = override_date_str[6:8]
            ovr_hr = override_date_str[8:10]
            ovr_min = override_date_str[10:12]
            ovr_sec = override_date_str[12:]
            override_date_str_arg = '{0} {1} {2} {3} {4} {5}'.format(
                ovr_yr, ovr_mnt, ovr_day, ovr_hr, ovr_min, ovr_sec)
            override_date = time.strptime(override_date_str_arg, "%Y %m %d %H %M %S")
            override_timestamp = calendar.timegm(override_date)
        elif k == 'stub-addr':
            stub_addr = v.strip('"\'')
        elif k == 'features':
            feature_list = v.split(feature_list_delimiter)
            try:
                for f_item in feature_list:
                    if f_item.find(feature_pair_delimiter) != -1:
                        f_key, f_value = [x.strip()
                                          for x
                                          in f_item.split(feature_pair_delimiter, 1)]
                    else:
                        f_key = f_item.strip()
                        f_value = ""
                    features[f_key] = f_value
            except KeyError as ex:
                raise KeyError("can't parse features (%s) in config section (%s)" % (v, str(ex)))
        elif k == 'feature-list':
            try:
                f_key, f_value = [x.strip() for x in v.split(feature_pair_delimiter, 1)]
                if f_key not in features:
                    features[f_key] = []
                f_value = f_value.replace("{{INSTALL_DIR}}", installdir)
                features[f_key].append(f_value)
            except KeyError as ex:
                raise KeyError("can't parse feature-list (%s) in config section (%s)"
                               % (v, str(ex)))
        elif k == 'force-ipv6' and v.upper() == 'TRUE':
            sockfamily = socket.AF_INET6

    ctx = {
        "DO_NOT_QUERY_LOCALHOST": str(do_not_query_localhost).lower(),
        "FEATURES": features,
        "HARDEN_GLUE": str(harden_glue).lower(),
        "INSTALL_DIR": installdir,
        "QMIN": str(qmin).lower(),
        "TRUST_ANCHORS": trust_anchor_list,
        "TRUST_ANCHOR_FILES": trust_anchor_files.keys()
    }
    if stub_addr:
        ctx['ROOT_ADDR'] = stub_addr
        # determine and verify socket family for specified root address
        gai = socket.getaddrinfo(stub_addr, 53, sockfamily, 0,
                                 socket.IPPROTO_UDP, socket.AI_NUMERICHOST)
        assert len(gai) == 1
        sockfamily = gai[0][0]
    if not sockfamily:
        sockfamily = socket.AF_INET  # default to IPv4
    ctx['_SOCKET_FAMILY'] = sockfamily
    if override_timestamp:
        ctx['_OVERRIDE_TIMESTAMP'] = override_timestamp
    return (ctx, trust_anchor_files)


def parse_file(path):
    """ Parse scenario from a file. """

    aug = pydnstest.augwrap.AugeasWrapper(
        confpath=path, lens='Deckard', loadpath=os.path.dirname(__file__))
    node = aug.tree
    config = []
    for line in [c.value for c in node.match("/config/*")]:
        if line:
            if not line.startswith(';'):
                if '#' in line:
                    line = line[0:line.index('#')]
                # Break to key-value pairs
                # e.g.: ['minimization', 'on']
                kv = [x.strip() for x in line.split(':', 1)]
                if len(kv) >= 2:
                    config.append(kv)
    scenario = Scenario(node["/scenario"], posixpath.basename(node.path))
    return scenario, config
