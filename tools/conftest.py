import ipaddress


def pytest_addoption(parser):
    parser.addoption("--forwarder", action="append", help="IP of forwarder to test")


def pytest_generate_tests(metafunc):
    if 'forwarder' in metafunc.fixturenames:
        forwarder = metafunc.config.option.forwarder
        metafunc.parametrize("forwarder", [ipaddress.ip_address(f) for f in forwarder], ids=str)
