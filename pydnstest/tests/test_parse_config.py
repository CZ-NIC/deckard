""" This is unittest file for parse methods in scenario.py """
import os

from pydnstest.scenario import parse_config


def test_parse_config__trust_anchor():
    """Checks if trust-anchors are separated into files according to domain."""
    anchor1 = u'domain1.com.\t3600\tIN\tDS\t11901 7 1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    anchor2 = u'domain2.net.\t3600\tIN\tDS\t59835 7 1 cccccccccccccccccccccccccccccccccccccccc'
    anchor3 = u'domain1.com.\t3600\tIN\tDS\t11902 7 1 1111111111111111111111111111111111111111'
    anchors = [[u'trust-anchor', u'"{}"'.format(anchor1)],
               [u'trust-anchor', u'"{}"'.format(anchor2)],
               [u'trust-anchor', u'"{}"'.format(anchor3)]]
    args = (anchors, True, os.getcwd())
    _, ta_files = parse_config(*args)
    assert sorted(ta_files.values()) == sorted([[anchor1, anchor3], [anchor2]])
