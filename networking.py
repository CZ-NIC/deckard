from ipaddress import IPv4Network, IPv6Network, ip_address
from socket import AF_INET, AF_INET6

from pyroute2 import IPRoute
from pyroute2.netlink.rtnl import ndmsg
from pyroute2.netlink.exceptions import NetlinkError

DEFAULT_ROUTING_TABLE_ID = 254


class InterfaceManager:
    """Wrapper for the `ip` command."""

    def __init__(self,
                 interface="deckard",
                 ip4_range=IPv4Network('127.127.0.0/16'),
                 ip6_range=IPv6Network('fd00:dec::/32')):
        self.ip4_internal_range = ip4_range
        self.ip6_internal_range = ip6_range
        self.ip4_iterator = (host for host in ip4_range)
        self.ip6_iterator = (host for host in ip6_range)
        self.added_addresses = set()
        self.interface = interface

        self._ip = IPRoute()
        try:
            self._dev = self._setup_interface()
        except NetlinkError:
            raise RuntimeError(f"Couldn't set interface `{self.interface}` up.")

    def _setup_interface(self):
        """Set up a dummy interface with default route as well as loopback.
           This is done so the resulting PCAP contains as much of the communication
           as possible (including ICMP Destination unreachable packets etc.)."""

        # Create and set the interface up.
        self._ip.link("add", ifname=self.interface, kind="dummy")
        dev = self._ip.link_lookup(ifname=self.interface)[0]
        self._ip.link("set", index=dev, state="up")

        # Set up default route for both IPv6 and IPv4
        self._ip.neigh("add", dst='169.254.1.1', lladdr='21:21:21:21:21:21',
                       state=ndmsg.states['permanent'], ifindex=dev)
        self._ip.neigh("add", family=AF_INET6, dst='fe80::1', lladdr='21:21:21:21:21:21',
                       state=ndmsg.states['permanent'], ifindex=dev)
        self._ip.addr("add", index=dev, address="169.254.1.2", mask=24)
        self._ip.route("add", table=DEFAULT_ROUTING_TABLE_ID, gateway="169.254.1.1", oif=dev)
        self._ip.route("add", table=DEFAULT_ROUTING_TABLE_ID, family=AF_INET6,
                       gateway='fe80::1', oif=dev)

        # Set the loopback up as well since some of the packets go through there.
        lo = self._ip.link_lookup(ifname="lo")[0]
        self._ip.link("set", index=lo, state="up")

        # Return internal interface ID for later use
        return dev

    def assign_internal_address(self, sockfamily) -> str:
        """Add and return new address from the internal range"""
        try:
            if sockfamily == AF_INET:
                a = str(next(self.ip4_iterator))
            elif sockfamily == AF_INET6:
                a = str(next(self.ip6_iterator))
            else:
                raise ValueError(f"Unknown sockfamily {sockfamily}")
        except StopIteration:
            raise RuntimeError("Out of addresses.")

        self._add_address(a)
        return a

    def add_address(self, address: str, check_duplicate=False):
        """Add an arbitrary new address to the interface"""
        if address in self.added_addresses and check_duplicate:
            raise ValueError(f"Tried to add duplicate address {address}")
        if ip_address(address) in self.ip4_internal_range or \
           ip_address(address) in self.ip6_internal_range:
            raise ValueError(f"Address {address} in the internally reserved range.")
        self._add_address(address)

    def _add_address(self, address):
        try:
            self._ip.addr("add", index=self._dev, address=address, mask=24)
        except NetlinkError as e:
            if e.code != 17:  # 'RTNETLINK answers: File exists' is OK here
                raise ValueError(f"Couldn't add {address}")

        self.added_addresses.add(address)
