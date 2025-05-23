#!/usr/bin/env python3

import sys

import xml.etree.ElementTree as xml


def parse_junit_xml(filename):
    """
    Transform junit XML file into set of tuples:
    (test description, file name, test result)
    """
    results = set()
    suite = xml.parse(filename).getroot().find("testsuite")
    for case in suite:
        if case.find("failure") is not None:  # Because empty XML elements are falsey
            results.add((case.get("name"), case.get("name").split("'")[1], "FAILED"))
        elif case.find("skipped") is not None:
            results.add((case.get("name"), case.get("name").split("'")[1], "SKIPPED"))
        else:
            results.add((case.get("name"), case.get("name").split("'")[1], "PASSED"))

    return results


new = sys.argv[1]
old = sys.argv[2]
with open(sys.argv[3], encoding="utf-8") as f:
    modified_tests = [line.strip() for line in f.readlines()]

test_diffs = parse_junit_xml(old) ^ parse_junit_xml(new)
errorneous_rpls = [diff[1] for diff in test_diffs
                   if diff[1] not in modified_tests]
if errorneous_rpls:
    print('FAIL! Following tests changed their result without test modification:')
    for rpl in sorted(set(errorneous_rpls)):
        print(rpl)
    sys.exit(1)
