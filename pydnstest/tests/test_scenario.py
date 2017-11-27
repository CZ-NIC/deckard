""" This is unittest file for scenario.py """

import pytest

from pydnstest.scenario import Entry

RCODE_FLAGS = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED', 'YXDOMAIN',
               'YXRRSET', 'NXRRSET', 'NOTAUTH', 'NOTZONE', 'BADVERS']
OPCODE_FLAGS = ['QUERY', 'IQUERY', 'STATUS', 'NOTIFY', 'UPDATE']
FLAGS = ['QR', 'TC', 'AA', 'AD', 'RD', 'RA', 'CD']


def test_entry__get_flags():
    """Checks if all rcodes and opcodes are filtered out"""
    expected_flags = Entry.get_flags(FLAGS)
    for flag in RCODE_FLAGS + OPCODE_FLAGS:
        rcode_flags = Entry.get_flags(FLAGS + [flag])
        assert rcode_flags == expected_flags, \
            'Entry._get_flags does not filter out "{flag}"'.format(flag=flag)


def test_entry__get_rcode():
    """
    Checks if the error is raised for multiple rcodes
    checks if None is returned for no rcode
    checks if flags and opcode are filtered out
    """
    with pytest.raises(ValueError):
        Entry.get_rcode(RCODE_FLAGS[:2])

    assert Entry.get_rcode(FLAGS) is None
    assert Entry.get_rcode([]) is None

    for rcode in RCODE_FLAGS:
        given_rcode = Entry.get_rcode(FLAGS + OPCODE_FLAGS + [rcode])
        assert given_rcode is not None, 'Entry.get_rcode does not recognize {rcode}'.format(
            rcode=rcode)


def test_entry__get_opcode():
    """
    Checks if the error is raised for multiple opcodes
    checks if None is returned for no opcode
    checks if flags and opcode are filtered out
    """
    with pytest.raises(ValueError):
        Entry.get_opcode(OPCODE_FLAGS[:2])

    assert Entry.get_opcode(FLAGS) is None
    assert Entry.get_opcode([]) is None

    for opcode in OPCODE_FLAGS:
        given_rcode = Entry.get_opcode(FLAGS + RCODE_FLAGS + [opcode])
        assert given_rcode is not None, 'Entry.get_opcode does not recognize {opcode}'.format(
            opcode=opcode)
