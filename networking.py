import subprocess
from ipaddress import IPv4Network, IPv6Network, ip_address
from socket import AF_INET, AF_INET6


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

        try:
            self._setup_interface()
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Couldn't set interface `{self.interface}` up.")

    def _setup_interface(self):
        """Set up a dummy interface with default route as well as loopback.
           This is done so the resulting PCAP contains as much of the communication
           as possible (including ICMP Destination unreachable packets etc.)."""
        # Create and set the interface up.
        subprocess.run(["ip", "link", "add", "dev", self.interface, "type", "dummy"], check=True)
        subprocess.run(["ip", "link", "set", "dev", self.interface, "up"], check=True)
        # Set up default route for both IPv6 and IPv4
        subprocess.run(["ip", "nei", "add", "169.254.1.1", "lladdr", "21:21:21:21:21:21", "dev",
                        self.interface], check=True)
        subprocess.run(["ip", "-6", "nei", "add", "fe80::1", "lladdr", "21:21:21:21:21:21", "dev",
                        self.interface], check=True)
        subprocess.run(["ip", "addr", "add", "169.254.1.2/24", "dev", self.interface], check=True)
        subprocess.run(["ip", "route", "add", "default", "via", "169.254.1.1", "dev",
                        self.interface], check=True)
        subprocess.run(["ip", "-6", "route", "add", "default", "via", "fe80::1", "dev",
                        self.interface], check=True)
        # Set the loopback up as well since some of the packets go through there.
        subprocess.run(["ip", "link", "set", "dev", "lo", "up"], check=True)

    def asign_internal_address(self, sockfamily) -> str:
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
        self._add_address(address, check_duplicate)

    def _add_address(self, address, check_duplicate=False):
        try:
            subprocess.run(f"ip addr add {address} dev {self.interface}",
                           capture_output=True, check=True, shell=True)
        except subprocess.CalledProcessError as e:
            if e.stderr != b'RTNETLINK answers: File exists\n':
                raise ValueError(f"Couldn't add {address}")

        self.added_addresses.add(address)
