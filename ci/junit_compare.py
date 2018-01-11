#!/usr/bin/python3

import xml.etree.ElementTree as xml
import sys


def parse_xml(filename):
    results = set()
    root = xml.parse(filename).getroot()
    for case in root:
        if case.find("failure") is not None:  # Because empty XML elements are falsey
            results.add((case.get("name"), case.get("name").split("'")[1], "FAILED"))
        elif case.find("skipped") is not None:
            results.add((case.get("name"), case.get("name").split("'")[1], "SKIPPED"))
        else:
            results.add((case.get("name"), case.get("name").split("'")[1], "PASSED"))

    return results

new = sys.argv[1]
old = sys.argv[2]
modified_tests = [line.strip() for line in open(sys.argv[3]).readlines()]

for diff in parse_xml(old) ^ parse_xml(new):
    print(diff[1])
    if diff[1] not in modified_tests:
        print(diff)
