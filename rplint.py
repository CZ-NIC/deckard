#!/usr/bin/env python3

from contextlib import suppress
import glob
import itertools
import os
import sys

import dns.name

import pydnstest.augwrap
import pydnstest.matchpart
import pydnstest.scenario

RCODES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
          "NXRRSET", "NOTAUTH", "NOTZONE", "BADVERS", "BADSIG", "BADKEY", "BADTIME", "BADMODE",
          "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE"}
FLAGS = {"QR", "AA", "TC", "RD", "RA", "AD", "CD"}
SECTIONS = {"question", "answer", "authority", "additional"}


class RplintError(ValueError):
    pass


def get_line_number(file, char_number):
    pos = 0
    for number, line in enumerate(open(file)):
        pos += len(line)
        if pos >= char_number:
            return number + 2


def is_empty(iterable):
    try:
        next(iterable)
    except StopIteration:
        return True
    return False


class Entry:
    def __init__(self, node):
        self.match = {m.value for m in node.match("/match")}
        self.adjust = {a.value for a in node.match("/adjust")}
        self.authority = list(node.match("/section/authority/record"))
        self.reply = {r.value for r in node.match("/reply")}
        self.records = list(node.match("/section/*/record"))
        self.node = node


class Step:
    def __init__(self, node):
        self.node = node
        self.type = node["/type"].value
        try:
            self.entry = Entry(node["/entry"])
        except KeyError:
            self.entry = None


class RplintTest:
    def __init__(self, path):
        aug = pydnstest.augwrap.AugeasWrapper(confpath=os.path.realpath(path),
                                              lens='Deckard',
                                              loadpath=os.path.join(os.path.dirname(__file__),
                                                                    'pydnstest'))
        self.node = aug.tree
        self.name = os.path.basename(path)
        self.path = path

        _, self.config = pydnstest.scenario.parse_file(os.path.realpath(path))
        self.range_entries = [Entry(node) for node in self.node.match("/scenario/range/entry")]
        self.steps = [Step(node) for node in self.node.match("/scenario/step")]
        self.step_entries = [step.entry for step in self.steps if step.entry is not None]
        self.entries = self.range_entries + self.step_entries

        self.ranges = [pydnstest.scenario.Range(n) for n in self.node.match("/scenario/range")]

        self.results = None
        self.checks = [
                    #    entry_more_than_one_rcode,
                    #    entry_no_qname_qtype_copy_query,
                    #    entry_ns_in_authority,
                    #    range_overlapping_ips,
                    #    range_shadowing_match_rules,
                    #    step_check_answer_no_match,
                    #    step_query_match,
                    #    step_section_unchecked,
                    #    step_unchecked_match,
                    #    step_unchecked_rcode,
                    #    scenario_ad_or_rrsig_no_ta,
                    #    scenario_timestamp,
                    #    config_trust_anchor_trailing_period_missing,
                    #    step_duplicate_id
                       ]

    def run_checks(self):
        """returns True iff all tests passed"""
        self.results = ""
        failed = False
        for check in self.checks:
            fails = check(self)
            for fail in fails:
                pos = get_line_number(self.path, fail)
                self.results += " ".join(["line", str(pos), check.__name__, check.__doc__, "\n"])

        if self.results == "":
            return True
        return False

    def print_results(self):
        print(self.results)


def config_trust_anchor_trailing_period_missing(test):
    """Trust-anchor option in configuration contains domain without trailing period"""
    for conf in test.config:
        if conf[0] == "trust-anchor":
            if conf[1].split()[0][-1] != ".":
                return [0]
    return []


def scenario_timestamp(test):
    """RRSSIG record present in test but no val-override-date or val-override-timestamp in config"""
    rrsigs = []
    for entry in test.entries:
        for record in entry.records:
            if record["/type"].value == "RRSIG":
                rrsigs.append(record.char)
    if rrsigs:
        for k in test.config:
            if k[0] == "val-override-date" or k[0] == "val-override-timestamp":
                return []
    return rrsigs


def entry_no_qname_qtype_copy_query(test):
    """ENTRY without qname and qtype in MATCH and without copy_query in ADJUST"""
    fails = []
    for entry in test.range_entries:
        if ("qname" not in entry.match or "qtype" not in entry.match) \
	   and "question" not in entry.match:
            if "copy_query" not in entry.adjust:
                fails.append(entry.node.char)
    return fails


def entry_ns_in_authority(test):
    """ENTRY has authority section with NS records, consider using MATCH subdomain"""
    fails = []
    for entry in test.range_entries:
        if entry.authority and "subdomain" not in entry.match:
            for record in entry.authority:
                if record["/type"].value == "NS":
                    fails.append(entry.node.char)
    return fails


def entry_more_than_one_rcode(test):
    """ENTRY has more than one rcode in MATCH"""
    fails = []
    for entry in test.entries:
        if len(RCODES & entry.reply) > 1:
            fails.append(entry.node.char)
    return fails


def scenario_ad_or_rrsig_no_ta(test):
    """AD or RRSIG present in test but no trust-anchor present in config"""
    dnssec = []
    for entry in test.entries:
        if "AD" in entry.reply or "AD" in entry.match:
            dnssec.append(entry.node.char)
        else:
            for record in entry.records:
                if record["/type"].value == "RRSIG":
                    dnssec.append(entry.node.char)

    if dnssec:
        for k in test.config:
            if k[0] == "trust-anchor":
                return []
    return dnssec


def step_query_match(test):
    """STEP QUERY has a MATCH rule"""
    return [step.node.char for step in test.steps if step.type == "QUERY" and step.entry.match]


def step_check_answer_no_match(test):
    """ENTRY in STEP CHECK_ANSWER has no MATCH rule"""
    return [step.entry.node.char for step in test.steps if step.type == "CHECK_ANSWER"
            and not step.entry.match]


def step_unchecked_rcode(test):
    """ENTRY specifies rcode but STEP MATCH does not check for it."""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER" and "all" not in step.entry.match:
            if step.entry.reply & RCODES and "rcode" not in step.entry.match:
                fails.append(step.entry.node.char)
    return fails


def step_unchecked_match(test):
    """ENTRY specifies flags but MATCH does not check for them"""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER":
            entry = step.entry
            if "all" not in entry.match and entry.reply - RCODES and "flags" not in entry.match:
                fails.append(entry.node.char)
    return fails


def step_section_unchecked(test):
    """ENTRY has non-empty sections but MATCH does not check for all of them"""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER" and "all" not in step.entry.match:
            for section in SECTIONS:
                if not is_empty(step.node.match("/entry/section/" + section + "/*")):
                    if section not in step.entry.match:
                        fails.append(step.entry.node.char)
    return fails


def range_overlapping_ips(test):
    """RANGE has common IPs with some previous overlapping RANGE"""
    fails = []
    for r1, r2 in itertools.combinations(test.ranges, 2):
        # If the ranges overlap
        if min(r1.b, r2.b) >= max(r1.a, r2.a):
            if r1.addresses & r2.addresses:
                fails.append(r2.node.char)
    return fails


def range_shadowing_match_rules(test):
    """ENTRY has no effect since one of previous entries has the same or broader match rules"""
    fails = []
    for r in test.ranges:
        for e1, e2 in itertools.combinations(r.stored, 2):
            match1 = set(e1.match_fields)
            match2 = set(e2.match_fields)
            msg1 = e1.message
            msg2 = e2.message
            if match1 <= match2:
                with suppress(pydnstest.matchpart.DataMismatch):
                    if pydnstest.matchpart.compare_rrs(msg1.question, msg2.question):
                        fails.append(e2.node.char)
            if "subdomain" in match1:
                if msg1.question[0].name.is_superdomain(msg2.question[0].name):
                    match1.discard("subdomain")
                    match2.discard("subdomain")
                    if match1 >= match2:
                        msg1.question[0].name = dns.name.Name("")
                        msg2.question[0].name = dns.name.Name("")
                        with suppress(pydnstest.matchpart.DataMismatch):
                            if pydnstest.matchpart.compare_rrs(msg1.question, msg2.question):
                                fails.append(e2.node.char)
    return fails


def step_duplicate_id(test):
    """STEP has the same ID as one of previous ones"""
    fails = []
    step_numbers = set()
    for step in test.steps:
        if step.node.value in step_numbers:
            fails.append(step.node.char)
        else:
            step_numbers.add(step.node.value)
    return fails


# TODO: This will make sense after we fix how we handle defaults in deckard.aug and scenario.py
# We might just not use defaults altogether as testbound does
# if "copy_id" not in adjust:
#    entry_error(test, entry, "copy_id should be in ADJUST")

def test_run_rplint(rpl):
    t = RplintTest(rpl)
    passed = t.run_checks()
    if not passed:
        raise RplintError(t.results)

if __name__ == '__main__':
    try:
        test_path = sys.argv[1]
    except IndexError:
        print("usage: %s <path to rpl file>" % sys.argv[0])
        sys.exit(2)
    print("Linting %s" % test_path)
    t = RplintTest(test_path)
    passed = t.run_checks()
    t.print_results()

    if passed:
        sys.exit(0)
    sys.exit(1)
