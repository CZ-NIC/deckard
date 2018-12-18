import ipaddress

# These are IPs of a.ns.nic.cz
AUTHORITATIVE_SERVERS = [ipaddress.IPv4Address("194.0.12.1"),
                         ipaddress.IPv6Address("2001:678:f::1")]


def pytest_addoption(parser):
    parser.addoption("--forwarder", action="append", help="IP of forwarder to test")


def pytest_generate_tests(metafunc):
    if 'forwarder' in metafunc.fixturenames:
        forwarder = metafunc.config.option.forwarder
        metafunc.parametrize("forwarder", [ipaddress.ip_address(f) for f in forwarder], ids=str)
    if 'tcp' in metafunc.fixturenames:
        metafunc.parametrize("tcp", [False, True], ids=lambda x: "TCP" if x else "UDP")
    if 'server' in metafunc.fixturenames:
        metafunc.parametrize("server", AUTHORITATIVE_SERVERS, ids=str)
