"""Returns 1 if there is a DNSSEC DSA signature which is not 41 bytes long.\
0 otherwise.
"""

import os
import sys
import argparse
import dns
import pydnstest
import pydnstest.scenario
import pydnstest.augwrap


def parse(test):
    """ Parse the test"""
    _, config = pydnstest.scenario.parse_file(os.path.realpath(test))
    aug = pydnstest.augwrap.AugeasWrapper(
        confpath=os.path.realpath(test),
        lens='Deckard', loadpath="../pydnstest")
    node = aug.tree
    return config, node


def get_dsakeys(config, node):
    """ Make list of all DSA keys in the test"""
    dsakeys = []
    for conf in config:
        if conf[0] == "trust-anchor":
            conf[1] = conf[1][1:-1]
            trust_anchor = conf[1].split()
            for i, word in enumerate(trust_anchor):
                if word == "DS":
                    algorithm = trust_anchor[i + 2]
                    if algorithm in ("3", "DSA"):
                        dsakeys.append(trust_anchor[i + 1])

    for entry in node.match("/scenario/range/entry"):
        records = list(entry.match("/section/answer/record"))
        records.extend(list(entry.match("/section/authority/record")))
        records.extend(list(entry.match("/section/additional/record")))

        for record in records:
            if record["/type"].value == "DS":
                if record["/data"].value[1] in ["3", "DSA"]:
                    dsakeys.append(record["/data"].value[2])
    return dsakeys


def check_rrsig(node, dsakeys):
    """ Find records with wrong lenght of rrsig"""
    for key in dsakeys:  # pylint: disable=too-many-nested-blocks
        for entry in node.match("/scenario/range/entry"):
            records = list(entry.match("/section/answer/record"))
            records.extend(list(entry.match("/section/authority/record")))
            records.extend(list(entry.match("/section/additional/record")))

            for record in records:
                if record["/type"].value == "RRSIG":
                    rrset = dns.rrset.from_text(record["/domain"].value, 300,
                                                1, dns.rdatatype.RRSIG,
                                                record["/data"].value)
                    if rrset.items[0].key_tag == int(key):
                        if len(rrset.items[0].signature) != 41:
                            return True
    return False


def main():
    """Returns 1 if there is a DNSSEC DSA signature which is not 41 bytes long. \
    0 otherwise."""
    argparser = argparse.ArgumentParser()
    argparser.add_argument("file")
    args = argparser.parse_args()
    config, node = parse(args.file)
    dsakeys = get_dsakeys(config, node)
    bad_rrsig = check_rrsig(node, dsakeys)
    if bad_rrsig:
        sys.exit(1)
    else:
        sys.exit(0)

main()
