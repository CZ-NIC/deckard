import ipaddress

import pytest

def pytest_addoption(parser):
    parser.addoption("--forwarder", action="store", help="IP of forwarder to test")

def pytest_generate_tests(metafunc):
    if 'forwarder' in metafunc.fixturenames:
        forwarder = metafunc.config.option.forwarder
        metafunc.parametrize("forwarder", [ipaddress.ip_address(forwarder)], ids=str)
