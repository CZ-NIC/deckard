"""matchpart is used to compare two DNS messages using a single criterion"""

from typing import (  # noqa
    Any, Hashable, Sequence, Tuple, Union)

import dns.edns
import dns.rcode
import dns.set

MismatchValue = Union[str, Sequence[Any]]


class DataMismatch(Exception):
    def __init__(self, exp_val, got_val):
        super().__init__()
        self.exp_val = exp_val
        self.got_val = got_val

    @staticmethod
    def format_diff(exp: MismatchValue, got: MismatchValue) -> str:
        if isinstance(exp, list):
            # hack for unhashable RRsets
            exp = list(str(val) for val in exp)
            got = list(str(val) for val in got)
            extra = set(got) - set(exp)
            missing = set(exp) - set(got)
            notes = []
            if extra:
                notes.append(
                        '; got unexpected values {}'.format(DataMismatch.format_value(list(extra))))
            if missing:
                notes.append(
                        '; missing expected values {}'.format(DataMismatch.format_value(list(missing))))
            return ', '.join(notes)
        else:
            return ''


    @staticmethod
    def format_value(value: MismatchValue) -> str:
        if isinstance(value, list):
            if len(value) != len(set(str(item) for item in value)):
                note = ' (duplicite!) '
            else:
                note = ''
            return ' '.join([str(val) for val in value]) + note
        else:
            return str(value)

    def __str__(self) -> str:
        return 'expected "{}" got "{}"{}'.format(
            self.format_value(self.exp_val),
            self.format_value(self.got_val),
            self.format_diff(self.exp_val, self.got_val))

    def __eq__(self, other):
        return (isinstance(other, DataMismatch)
                and self.exp_val == other.exp_val
                and self.got_val == other.got_val)

    def __ne__(self, other):
        return not self.__eq__(other)

    @property
    def key(self) -> Tuple[Hashable, Hashable]:
        def make_hashable(value):
            if isinstance(value, (list, dns.set.Set)):
                value = (make_hashable(item) for item in value)
                value = tuple(value)
            return value

        return (make_hashable(self.exp_val), make_hashable(self.got_val))

    def __hash__(self) -> int:
        return hash(self.key)


def compare_val(exp, got):
    """Compare arbitraty objects, throw exception if different. """
    if exp != got:
        raise DataMismatch(exp, got)
    return True


def compare_rrs(expected, got):
    """ Compare lists of RR sets, throw exception if different. """
    for rr in expected:
        if rr not in got:
            raise DataMismatch(expected, got)
    for rr in got:
        if rr not in expected:
            raise DataMismatch(expected, got)
    if len(expected) != len(got):
        raise DataMismatch(expected, got)
    return True


def compare_rrs_types(exp_val, got_val, skip_rrsigs):
    """sets of RR types in both sections must match"""
    def rr_ordering_key(rrset):
        if rrset.covers:
            return rrset.covers, 1  # RRSIGs go to the end of RRtype list
        else:
            return rrset.rdtype, 0

    def key_to_text(rrtype, rrsig):
        if not rrsig:
            return dns.rdatatype.to_text(rrtype)
        else:
            return 'RRSIG(%s)' % dns.rdatatype.to_text(rrtype)

    if skip_rrsigs:
        exp_val = (rrset for rrset in exp_val
                   if rrset.rdtype != dns.rdatatype.RRSIG)
        got_val = (rrset for rrset in got_val
                   if rrset.rdtype != dns.rdatatype.RRSIG)

    exp_types = frozenset(rr_ordering_key(rrset) for rrset in exp_val)
    got_types = frozenset(rr_ordering_key(rrset) for rrset in got_val)
    if exp_types != got_types:
        exp_types = tuple(key_to_text(*i) for i in sorted(exp_types))
        got_types = tuple(key_to_text(*i) for i in sorted(got_types))
        raise DataMismatch(exp_types, got_types)


def check_question(question):
    if len(question) > 2:
        raise NotImplementedError("More than one record in QUESTION SECTION.")


def match_opcode(exp, got):
    return compare_val(exp.opcode(),
                       got.opcode())


def match_qtype(exp, got):
    check_question(exp.question)
    check_question(got.question)
    if not exp.question and not got.question:
        return True
    if not exp.question:
        raise DataMismatch("<empty question>", got.question[0].rdtype)
    if not got.question:
        raise DataMismatch(exp.question[0].rdtype, "<empty question>")
    return compare_val(exp.question[0].rdtype,
                       got.question[0].rdtype)


def match_qname(exp, got):
    check_question(exp.question)
    check_question(got.question)
    if not exp.question and not got.question:
        return True
    if not exp.question:
        raise DataMismatch("<empty question>", got.question[0].name)
    if not got.question:
        raise DataMismatch(exp.question[0].name, "<empty question>")
    return compare_val(exp.question[0].name,
                       got.question[0].name)


def match_qcase(exp, got):
    check_question(exp.question)
    check_question(got.question)
    if not exp.question and not got.question:
        return True
    if not exp.question:
        raise DataMismatch("<empty question>", got.question[0].name.labels)
    if not got.question:
        raise DataMismatch(exp.question[0].name.labels, "<empty question>")
    return compare_val(exp.question[0].name.labels,
                       got.question[0].name.labels)


def match_subdomain(exp, got):
    if not exp.question:
        return True
    if got.question:
        qname = got.question[0].name
    else:
        qname = dns.name.root
    if exp.question[0].name.is_superdomain(qname):
        return True
    raise DataMismatch(exp, got)


def match_flags(exp, got):
    return compare_val(dns.flags.to_text(exp.flags),
                       dns.flags.to_text(got.flags))


def match_rcode(exp, got):
    return compare_val(dns.rcode.to_text(exp.rcode()),
                       dns.rcode.to_text(got.rcode()))


def match_answer(exp, got):
    return compare_rrs(exp.answer,
                       got.answer)


def match_answertypes(exp, got):
    return compare_rrs_types(exp.answer,
                             got.answer, skip_rrsigs=True)


def match_answerrrsigs(exp, got):
    return compare_rrs_types(exp.answer,
                             got.answer, skip_rrsigs=False)


def match_authority(exp, got):
    return compare_rrs(exp.authority,
                       got.authority)


def match_additional(exp, got):
    return compare_rrs(exp.additional,
                       got.additional)


def match_edns(exp, got):
    if got.edns != exp.edns:
        raise DataMismatch(exp.edns,
                           got.edns)
    if got.payload != exp.payload:
        raise DataMismatch(exp.payload,
                           got.payload)


def match_nsid(exp, got):
    nsid_opt = None
    for opt in exp.options:
        if opt.otype == dns.edns.NSID:
            nsid_opt = opt
            break
    # Find matching NSID
    for opt in got.options:
        if opt.otype == dns.edns.NSID:
            if not nsid_opt:
                raise DataMismatch(None, opt.data)
            if opt == nsid_opt:
                return True
            else:
                raise DataMismatch(nsid_opt.data, opt.data)
    if nsid_opt:
        raise DataMismatch(nsid_opt.data, None)
    return True


MATCH = {"opcode": match_opcode, "qtype": match_qtype, "qname": match_qname, "qcase": match_qcase,
         "subdomain": match_subdomain, "flags": match_flags, "rcode": match_rcode,
         "answer": match_answer, "answertypes": match_answertypes,
         "answerrrsigs": match_answerrrsigs, "authority": match_authority,
         "additional": match_additional, "edns": match_edns,
         "nsid": match_nsid}


def match_part(exp, got, code):
    try:
        return MATCH[code](exp, got)
    except KeyError:
        raise NotImplementedError('unknown match request "%s"' % code)
