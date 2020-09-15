from abc import ABC
import binascii
import calendar
from datetime import datetime
import logging
import os  # requires posix
import random
import socket
import struct
import time
from typing import Optional

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rrset
import dns.tsigkeyring

import pydnstest.augwrap
import pydnstest.matchpart
import pydnstest.mock_client


def str2bool(v):
    """ Return conversion of JSON-ish string value to boolean. """
    return v.lower() in ('yes', 'true', 'on', '1')


# Global statistics
g_rtt = 0.0
g_nqueries = 0


class DNSBlob(ABC):
    def to_wire(self) -> bytes:
        raise NotImplementedError

    def __str__(self) -> str:
        return '<DNSBlob>'


class DNSMessage(DNSBlob):
    def __init__(self, message: dns.message.Message) -> None:
        assert message is not None
        self.message = message

    def to_wire(self) -> bytes:
        return self.message.to_wire(max_size=65535)

    def __str__(self) -> str:
        return str(self.message)


class DNSReply(DNSMessage):
    def __init__(
                self,
                message: dns.message.Message,
                query: Optional[dns.message.Message] = None,
                copy_id: bool = False,
                copy_query: bool = False
            ) -> None:
        super().__init__(message)
        if copy_id or copy_query:
            if query is None:
                raise ValueError("query must be provided to adjust copy_id/copy_query")
            self.adjust_reply(query, copy_id, copy_query)

    def adjust_reply(
                self,
                query: dns.message.Message,
                copy_id: bool = True,
                copy_query: bool = True
            ) -> None:
        answer = dns.message.from_wire(self.message.to_wire(),
                                       xfr=self.message.xfr,
                                       one_rr_per_rrset=True)
        answer.use_edns(query.edns, query.ednsflags, options=self.message.options)
        if copy_id:
            answer.id = query.id
            # Copy letter-case if the template has QD
            if answer.question:
                answer.question[0].name = query.question[0].name
        if copy_query:
            answer.question = query.question
        # Re-set, as the EDNS might have reset the ext-rcode
        answer.set_rcode(self.message.rcode())

        # sanity check: adjusted answer should be almost the same
        assert len(answer.answer) == len(self.message.answer)
        assert len(answer.authority) == len(self.message.authority)
        assert len(answer.additional) == len(self.message.additional)
        self.message = answer


class DNSReplyRaw(DNSBlob):
    def __init__(
                self,
                wire: bytes,
                query: Optional[dns.message.Message] = None,
                copy_id: bool = False
            ) -> None:
        assert wire is not None
        self.wire = wire
        if copy_id:
            if query is None:
                raise ValueError("query must be provided to adjust copy_id")
            self.adjust_reply(query, copy_id)

    def adjust_reply(
                self,
                query: dns.message.Message,
                raw_id: bool = True
            ) -> None:
        if raw_id:
            if len(self.wire) < 2:
                raise ValueError(
                    'wire data must contain at least 2 bytes to adjust query id')
            raw_answer = bytearray(self.wire)
            struct.pack_into('!H', raw_answer, 0, query.id)
            self.wire = bytes(raw_answer)

    def to_wire(self) -> bytes:
        return self.wire

    def __str__(self) -> str:
        return '<DNSReplyRaw>'


class DNSReplyServfail(DNSMessage):
    def __init__(self, query: dns.message.Message) -> None:
        message = dns.message.make_response(query)
        message.set_rcode(dns.rcode.SERVFAIL)
        super().__init__(message)


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
        self.raw_data = self.process_raw()

        # MATCH
        self.match_fields = self.process_match()

        # FLAGS (old alias REPLY)
        self.process_reply_line()

        # ADJUST
        self.adjust_fields = {m.value for m in node.match("/adjust")}

        # MANDATORY
        try:
            self.mandatory = list(node.match("/mandatory"))[0]
        except (KeyError, IndexError):
            self.mandatory = None

        # TSIG
        self.process_tsig()

        # SECTIONS & RECORDS
        self.sections = self.process_sections()

    def process_raw(self):
        try:
            return binascii.unhexlify(self.node["/raw"].value)
        except KeyError:
            return None

    def process_match(self):
        try:
            self.node["/match_present"]
        except KeyError:
            return None

        fields = set(m.value for m in self.node.match("/match"))

        if 'all' in fields:
            fields.remove("all")
            fields |= set(["opcode", "qtype", "qname", "flags",
                           "rcode", "answer", "authority", "additional"])

        if 'question' in fields:
            fields.remove("question")
            fields |= set(["qtype", "qname"])

        return fields

    def process_reply_line(self):
        """Extracts flags, rcode and opcode from given node and adjust dns message accordingly"""
        fields = [f.value for f in self.node.match("/reply")]
        if 'DO' in fields:
            self.message.want_dnssec(True)
        opcode = self.get_opcode(fields)
        rcode = self.get_rcode(fields)
        self.message.flags = self.get_flags(fields)
        if rcode is not None:
            self.message.set_rcode(rcode)
        if opcode is not None:
            self.message.set_opcode(opcode)

    def process_tsig(self):
        try:
            tsig = list(self.node.match("/tsig"))[0]
            tsig_keyname = tsig["/keyname"].value
            tsig_secret = tsig["/secret"].value
            keyring = dns.tsigkeyring.from_text({tsig_keyname: tsig_secret})
            self.message.use_tsig(keyring=keyring, keyname=tsig_keyname)
        except (KeyError, IndexError):
            pass

    def process_sections(self):
        sections = set()
        for section in self.node.match("/section/*"):
            section_name = os.path.basename(section.path)
            sections.add(section_name)
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
                            rd[1] = '{}'.format(dns.dnssec.algorithm_from_text(rd[1]))
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
        return sections

    def __str__(self):
        txt = 'ENTRY_BEGIN\n'
        if self.raw_data is None:
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
        if self.raw_data is not None:
            txt += 'RAW\n'
            if self.raw_data:
                txt += binascii.hexlify(self.raw_data)
            else:
                txt += 'NULL'
            txt += '\n'
        txt += 'ENTRY_END\n'
        return txt

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
        if not rcodes:
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
        if not opcodes:
            return None
        return opcodes[0]

    def match(self, msg):
        """ Compare scripted reply to given message based on match criteria. """
        for code in self.match_fields:
            try:
                pydnstest.matchpart.match_part(self.message, msg, code)
            except pydnstest.matchpart.DataMismatch as ex:
                errstr = '%s in the response:\n%s' % (str(ex), msg.to_text())
                # TODO: cisla radku
                raise ValueError("%s, \"%s\": %s" % (self.node.span, code, errstr)) from None

    def cmp_raw(self, raw_value):
        assert self.raw_data is not None
        expected = None
        if self.raw_data is not None:
            expected = binascii.hexlify(self.raw_data)
        got = None
        if raw_value is not None:
            got = binascii.hexlify(raw_value)
        if expected != got:
            raise ValueError("raw message comparsion failed: expected %s got %s" % (expected, got))

    def reply(self, query) -> Optional[DNSBlob]:
        if 'do_not_answer' in self.adjust_fields:
            return None
        if self.raw_data is not None:
            raw_id = 'raw_id' in self.adjust_fields
            assert self.raw_data is not None
            return DNSReplyRaw(self.raw_data, query, raw_id)
        copy_id = 'copy_id' in self.adjust_fields
        copy_query = 'copy_query' in self.adjust_fields
        return DNSReply(self.message, query, copy_id, copy_query)

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
        assert self.a <= self.b

        address = node["/address"].value
        self.addresses = {address} if address is not None else set()
        self.addresses |= {a.value for a in node.match("/address/*")}
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

    def eligible(self, ident, address):
        """ Return true if this range is eligible for fetching reply. """
        if self.a <= ident <= self.b:
            return (None is address
                    or set() == self.addresses
                    or address in self.addresses)
        return False

    def reply(self, query: dns.message.Message) -> Optional[DNSBlob]:
        """Get answer for given query (adjusted if needed)."""
        self.received += 1
        for candidate in self.stored:
            try:
                candidate.match(query)
                resp = candidate.reply(query)
                # Probabilistic loss
                if 'LOSS' in self.args:
                    if random.random() < float(self.args['LOSS']):
                        return DNSReplyServfail(query)
                self.sent += 1
                candidate.fired += 1
                return resp
            except ValueError:
                pass
        return DNSReplyServfail(query)


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
            choice, tcp, src_address = None, False, ctx.deckard_address
            return self.__query(ctx, tcp=tcp, choice=choice, src_address=src_address)
        elif self.type == 'CHECK_OUT_QUERY':  # ignore
            self.log.info('')
            return None
        elif self.type == 'CHECK_ANSWER' or self.type == 'ANSWER':
            self.log.info('')
            return self.__check_answer(ctx)
        elif self.type == 'TIME_PASSES ELAPSE':
            self.log.info('')
            return self.__time_passes()
        elif self.type == 'REPLY' or self.type == 'MOCK':
            self.log.info('')
            return None
        else:
            raise NotImplementedError('step %03d type %s unsupported' % (self.id, self.type))

    def __check_answer(self, ctx):
        """ Compare answer from previously resolved query. """
        if not self.data:
            raise ValueError("response definition required")
        expected = self.data[0]
        if expected.raw_data is not None:
            self.log.debug("raw answer: %s", ctx.last_raw_answer.to_text())
            expected.cmp_raw(ctx.last_raw_answer)
        else:
            if ctx.last_answer is None:
                raise ValueError("no answer from preceding query")
            self.log.debug("answer: %s", ctx.last_answer.to_text())
            expected.match(ctx.last_answer)

    def __query(self, ctx, tcp=False, choice=None, src_address=None):
        """
        Send query and wait for an answer (if the query is not RAW).

        The received answer is stored in self.answer and ctx.last_answer.
        """
        if not self.data:
            raise ValueError("query definition required")
        if self.data[0].raw_data is not None:
            data_to_wire = self.data[0].raw_data
        else:
            # Don't use a message copy as the EDNS data portion is not copied.
            data_to_wire = self.data[0].message.to_wire()
        if choice is None or not choice:
            choice = list(ctx.client.keys())[0]
        if choice not in ctx.client:
            raise ValueError('step %03d invalid QUERY target: %s' % (self.id, choice))

        tstart = datetime.now()

        # Send query and wait for answer
        answer = None
        sock = pydnstest.mock_client.setup_socket(ctx.client[choice][0],
                                                  ctx.client[choice][1],
                                                  tcp,
                                                  src_address=src_address)
        with sock:
            pydnstest.mock_client.send_query(sock, data_to_wire)
            if self.data[0].raw_data is None:
                answer = pydnstest.mock_client.get_answer(sock)

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


class Scenario:
    log = logging.getLogger('pydnstest.scenatio.Scenario')

    def __init__(self, node, filename, deckard_address=None):
        """ Initialize scenario with description. """
        self.node = node
        self.info = node.value
        self.file = filename
        self.ranges = [Range(n) for n in node.match("/range")]
        self.current_range = None
        self.steps = [Step(n) for n in node.match("/step")]
        self.current_step = None
        self.client = {}
        self.deckard_address = deckard_address

    def __str__(self):
        txt = 'SCENARIO_BEGIN'
        if self.info:
            txt += ' {0}'.format(self.info)
        txt += '\n'
        for range_ in self.ranges:
            txt += str(range_)
        for step in self.steps:
            txt += str(step)
        txt += "\nSCENARIO_END"
        return txt

    def reply(self, query: dns.message.Message, address=None) -> Optional[DNSBlob]:
        """Generate answer packet for given query."""
        current_step_id = self.current_step.id
        # Unknown address, select any match
        # TODO: workaround until the server supports stub zones
        all_addresses = set()  # type: ignore
        for rng in self.ranges:
            all_addresses.update(rng.addresses)
        if address not in all_addresses:
            address = None
        # Find current valid query response range
        for rng in self.ranges:
            if rng.eligible(current_step_id, address):
                self.current_range = rng
                return rng.reply(query)
        # Find any prescripted one-shot replies
        for step in self.steps:
            if step.id < current_step_id or step.type != 'REPLY':
                continue
            try:
                candidate = step.data[0]
                candidate.match(query)
                step.data.remove(candidate)
                return candidate.reply(query)
            except (IndexError, ValueError):
                pass
        return DNSReplyServfail(query)

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
                                             (step.id, step.next_if_fail)) from ex
                        next_step = next_steps[0]
                        if next_step < len(self.steps):
                            i = next_step
                        else:
                            raise ValueError('step %d: Can''t branch to NEXT value "%d"' %
                                             (step.id, step.next_if_fail)) from ex
                    continue
                ex_details = ex if self.log.isEnabledFor(logging.DEBUG) else None
                raise ValueError('%s step %d %s' % (self.file, step.id, str(ex))) from ex_details
            i += 1

        for r in self.ranges:
            for e in r.stored:
                if e.mandatory and e.fired == 0:
                    # TODO: cisla radku
                    raise ValueError('Mandatory section at %s not fired' % e.mandatory.span)


def get_next(file_in, skip_empty=True):
    """ Return next token from the input stream. """
    while True:
        line = file_in.readline()
        if not line:
            return False
        quoted, escaped = False, False
        for i, char in enumerate(line):
            if char == '\\':
                escaped = not escaped
            if not escaped and char == '"':
                quoted = not quoted
            if char == ';' and not quoted:
                line = line[0:i]
                break
            if char != '\\':
                escaped = False
        tokens = ' '.join(line.strip().split()).split()
        if not tokens:
            if skip_empty:
                continue
            return '', []
        op = tokens.pop(0)
        return op, tokens


def parse_config(scn_cfg, qmin, installdir):  # FIXME: pylint: disable=too-many-statements
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
    negative_ta_list = []
    stub_addr = None
    override_timestamp = None

    features = {}
    feature_list_delimiter = ';'
    feature_pair_delimiter = '='

    for k, v in scn_cfg:
        # Enable selectively for some tests
        if k == 'do-not-query-localhost':
            do_not_query_localhost = str2bool(v)
        elif k == 'domain-insecure':
            negative_ta_list.append(v)
        elif k == 'harden-glue':
            harden_glue = str2bool(v)
        elif k == 'query-minimization':
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
                raise KeyError("can't parse features (%s) in config section (%s)"
                               % (v, str(ex))) from ex
        elif k == 'feature-list':
            try:
                f_key, f_value = [x.strip() for x in v.split(feature_pair_delimiter, 1)]
                if f_key not in features:
                    features[f_key] = []
                f_value = f_value.replace("{{INSTALL_DIR}}", installdir)
                features[f_key].append(f_value)
            except KeyError as ex:
                raise KeyError("can't parse feature-list (%s) in config section (%s)"
                               % (v, str(ex))) from ex
        elif k == 'force-ipv6' and v.upper() == 'TRUE':
            sockfamily = socket.AF_INET6
        else:
            raise NotImplementedError('unsupported CONFIG key "%s"' % k)

    ctx = {
        "DO_NOT_QUERY_LOCALHOST": str(do_not_query_localhost).lower(),
        "NEGATIVE_TRUST_ANCHORS": negative_ta_list,
        "FEATURES": features,
        "HARDEN_GLUE": str(harden_glue).lower(),
        "INSTALL_DIR": installdir,
        "QMIN": str(qmin).lower(),
        "TRUST_ANCHORS": trust_anchor_list,
        "TRUST_ANCHOR_FILES": trust_anchor_files
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
    return ctx


def parse_file(path, deckard_address=None):
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
    scenario = Scenario(node["/scenario"], os.path.basename(node.path), deckard_address)
    return scenario, config
