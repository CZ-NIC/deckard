#!/usr/bin/env python3

from contextlib import suppress
import glob
import itertools
import os
import sys
from typing import Any, Callable, Iterable, Iterator, Optional, List, Union, Set

import dns.name

import pydnstest.augwrap
import pydnstest.matchpart
import pydnstest.scenario

Element = Union["Entry", "Step", pydnstest.scenario.Range]

RCODES = {"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET",
          "NXRRSET", "NOTAUTH", "NOTZONE", "BADVERS", "BADSIG", "BADKEY", "BADTIME", "BADMODE",
          "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE"}
FLAGS = {"QR", "AA", "TC", "RD", "RA", "AD", "CD"}
SECTIONS = {"question", "answer", "authority", "additional"}


class RplintError(ValueError):
    def __init__(self, fails):
        msg = ""
        for fail in fails:
            msg += str(fail) + "\n"
        super().__init__(msg)


def get_line_number(file: str, char_number: int) -> int:
    pos = 0
    for number, line in enumerate(open(file)):
        pos += len(line)
        if pos >= char_number:
            return number + 2
    return 0


def is_empty(iterable: Iterator[Any]) -> bool:
    try:
        next(iterable)
    except StopIteration:
        return True
    return False


class Entry:
    def __init__(self, node: pydnstest.augwrap.AugeasNode) -> None:
        self.match = {m.value for m in node.match("/match")}
        self.adjust = {a.value for a in node.match("/adjust")}
        self.authority = list(node.match("/section/authority/record"))
        self.reply = {r.value for r in node.match("/reply")}
        self.records = list(node.match("/section/*/record"))
        self.node = node


class Step:
    def __init__(self, node: pydnstest.augwrap.AugeasNode) -> None:
        self.node = node
        self.type = node["/type"].value
        try:
            self.entry = Entry(node["/entry"])  # type: Optional[Entry]
        except KeyError:
            self.entry = None


class RplintFail:
    def __init__(self, test: "RplintTest",
                 element: Optional[Element] = None,
                 etc: str = "") -> None:
        self.path = test.path
        self.element = element  # type: Optional[Element]
        self.line = get_line_number(self.path, element.node.char if element is not None else 0)
        self.etc = etc
        self.check = None  # type: Optional[Callable[[RplintTest], List[RplintFail]]]

    def __str__(self):
        if self.etc:
            return "{}:{} {}: {} ({})".format(os.path.basename(self.path), self.line,
                                              self.check.__name__, self.check.__doc__, self.etc)
        return "{}:{} {}: {}".format(os.path.basename(self.path), self.line, self.check.__name__,
                                     self.check.__doc__)


class RplintTest:
    def __init__(self, path: str) -> None:
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

        self.fails = None  # type: Optional[List[RplintFail]]
        self.checks = [
            entry_more_than_one_rcode,
            entry_no_qname_qtype_copy_query,
            # Commented out for now until we implement selective turning off of checks
            # entry_ns_in_authority,
            range_overlapping_ips,
            range_shadowing_match_rules,
            step_check_answer_no_match,
            step_query_match,
            step_section_unchecked,
            step_unchecked_match,
            step_unchecked_rcode,
            scenario_ad_or_rrsig_no_ta,
            scenario_timestamp,
            config_trust_anchor_trailing_period_missing,
            step_duplicate_id,
        ]

    def run_checks(self) -> bool:
        """returns True iff all tests passed"""
        self.fails = []
        for check in self.checks:
            fails = check(self)
            for fail in fails:
                fail.check = check
            self.fails += fails

        if self.fails == []:
            return True
        return False

    def print_fails(self) -> None:
        if self.fails is None:
            raise RuntimeError("Maybe you should run some test first…")
        for fail in self.fails:
            print(fail)


def config_trust_anchor_trailing_period_missing(test: RplintTest) -> List[RplintFail]:
    """Trust-anchor option in configuration contains domain without trailing period"""
    for conf in test.config:
        if conf[0] == "trust-anchor":
            if conf[1].split()[0][-1] != ".":
                return [RplintFail(test, etc=conf[1])]
    return []


def scenario_timestamp(test: RplintTest) -> List[RplintFail]:
    """RRSSIG record present in test but no val-override-date or val-override-timestamp in config"""
    rrsigs = []
    for entry in test.entries:
        for record in entry.records:
            if record["/type"].value == "RRSIG":
                rrsigs.append(RplintFail(test, entry))
    if rrsigs:
        for k in test.config:
            if k[0] == "val-override-date" or k[0] == "val-override-timestamp":
                return []
    return rrsigs


def entry_no_qname_qtype_copy_query(test: RplintTest) -> List[RplintFail]:
    """ENTRY without qname and qtype in MATCH and without copy_query in ADJUST"""
    fails = []
    for entry in test.range_entries:
        if "question" not in entry.match and ("qname" not in entry.match or
                                              "qtype" not in entry.match):
            if "copy_query" not in entry.adjust:
                fails.append(RplintFail(test, entry))
    return fails


def entry_ns_in_authority(test: RplintTest) -> List[RplintFail]:
    """ENTRY has authority section with NS records, consider using MATCH subdomain"""
    fails = []
    for entry in test.range_entries:
        if entry.authority and "subdomain" not in entry.match:
            for record in entry.authority:
                if record["/type"].value == "NS":
                    fails.append(RplintFail(test, entry))
    return fails


def entry_more_than_one_rcode(test: RplintTest) -> List[RplintFail]:
    """ENTRY has more than one rcode in MATCH"""
    fails = []
    for entry in test.entries:
        if len(RCODES & entry.reply) > 1:
            fails.append(RplintFail(test, entry))
    return fails


def scenario_ad_or_rrsig_no_ta(test: RplintTest) -> List[RplintFail]:
    """AD or RRSIG present in test but no trust-anchor present in config"""
    dnssec = []
    for entry in test.entries:
        if "AD" in entry.reply or "AD" in entry.match:
            dnssec.append(RplintFail(test, entry))
        else:
            for record in entry.records:
                if record["/type"].value == "RRSIG":
                    dnssec.append(RplintFail(test, entry))

    if dnssec:
        for k in test.config:
            if k[0] == "trust-anchor":
                return []
    return dnssec


def step_query_match(test: RplintTest) -> List[RplintFail]:
    """STEP QUERY has a MATCH rule"""
    return [RplintFail(test, step) for step in test.steps if step.type == "QUERY" and
            step.entry and step.entry.match]


def step_check_answer_no_match(test: RplintTest) -> List[RplintFail]:
    """ENTRY in STEP CHECK_ANSWER has no MATCH rule"""
    return [RplintFail(test, step) for step in test.steps if step.type == "CHECK_ANSWER" and
            step.entry and not step.entry.match]


def step_unchecked_rcode(test: RplintTest) -> List[RplintFail]:
    """ENTRY specifies rcode but STEP MATCH does not check for it."""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER" and step.entry and "all" not in step.entry.match:
            if step.entry.reply & RCODES and "rcode" not in step.entry.match:
                fails.append(RplintFail(test, step.entry))
    return fails


def step_unchecked_match(test: RplintTest) -> List[RplintFail]:
    """ENTRY specifies flags but MATCH does not check for them"""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER":
            entry = step.entry
            if entry and "all" not in entry.match and entry.reply - RCODES and \
               "flags" not in entry.match:
                fails.append(RplintFail(test, entry, str(entry.reply - RCODES)))
    return fails


def step_section_unchecked(test: RplintTest) -> List[RplintFail]:
    """ENTRY has non-empty sections but MATCH does not check for all of them"""
    fails = []
    for step in test.steps:
        if step.type == "CHECK_ANSWER" and step.entry and "all" not in step.entry.match:
            for section in SECTIONS:
                if not is_empty(step.node.match("/entry/section/" + section + "/*")):
                    if section not in step.entry.match:
                        fails.append(RplintFail(test, step.entry, section))
    return fails


def range_overlapping_ips(test: RplintTest) -> List[RplintFail]:
    """RANGE has common IPs with some previous overlapping RANGE"""
    fails = []
    for r1, r2 in itertools.combinations(test.ranges, 2):
        # If the ranges overlap
        if min(r1.b, r2.b) >= max(r1.a, r2.a):
            if r1.addresses & r2.addresses:
                info = "previous range on line %d" % get_line_number(test.path, r1.node.char)
                fails.append(RplintFail(test, r2, info))
    return fails


def range_shadowing_match_rules(test: RplintTest) -> List[RplintFail]:
    """ENTRY has no effect since one of previous entries has the same or broader match rules"""
    fails = []
    for r in test.ranges:
        for e1, e2 in itertools.combinations(r.stored, 2):
            try:
                e1.match(e2.message)
                info = "previous entry on line %d" % get_line_number(test.path, e1.node.char)
                if e1.match_fields > e2.match_fields:
                    continue
                fails.append(RplintFail(test, e2, info))
            # IndexError is here especially because of empty question section in rpls
            except (ValueError, IndexError):
                pass
    return fails


def step_duplicate_id(test: RplintTest) -> List[RplintFail]:
    """STEP has the same ID as one of previous ones"""
    fails = []
    step_numbers = set()  # type: Set[int]
    for step in test.steps:
        if step.node.value in step_numbers:
            fails.append(RplintFail(test, step))
        else:
            step_numbers.add(step.node.value)
    return fails


# TODO: This will make sense after we fix how we handle defaults in deckard.aug and scenario.py
# We might just not use defaults altogether as testbound does
# if "copy_id" not in adjust:
#    entry_error(test, entry, "copy_id should be in ADJUST")

def test_run_rplint(rpl_path: str) -> None:
    t = RplintTest(rpl_path)
    passed = t.run_checks()
    if not passed:
        raise RplintError(t.fails)


if __name__ == '__main__':
    try:
        test_path = sys.argv[1]
    except IndexError:
        print("usage: %s <path to rpl file>" % sys.argv[0])
        sys.exit(2)
    if not os.path.isfile(test_path):
        print("rplint.py works on single file only.")
        print("Use rplint.sh with --scenarios=<directory with rpls> to run on rpls.")
        sys.exit(2)
    print("Linting %s" % test_path)
    t = RplintTest(test_path)
    passed = t.run_checks()
    t.print_fails()

    if passed:
        sys.exit(0)
    sys.exit(1)
