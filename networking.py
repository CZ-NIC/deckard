from ipaddress import IPv4Network, IPv6Network, ip_address
import subprocess
from socket import AF_INET, AF_INET6

class LoopbackManager:

    def __init__(self,
                 ip4_range=IPv4Network('127.127.0.0/16'),
                 ip6_range=IPv6Network('fd00:dec::/32'),
                ):
        self.ip4_internal_range = ip4_range
        self.ip6_internal_range = ip6_range
        self.ip4_iterator = (host for host in ip4_range)
        self.ip6_iterator = (host for host in ip6_range)
        self.added_addresses = set()

        try:
            subprocess.run(f"ip link set dev lo up", check=True, shell=True)
        except subprocess.CalledProcessError:
            raise RuntimeError(f"Couldn't set lo device up.")

    def add_internal_address(self, sockfamily) -> str:
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

    def add_address(self, address: str):
        if ip_address(address) in self.ip4_internal_range or ip_address(address) in self.ip6_internal_range:
            raise ValueError(f"Address {address} in the internally reserved range.")
        self._add_address(address)

    def _add_address(self, address, check_duplicate=False):
        if address in self.added_addresses and check_duplicate:
            raise ValueError(f"Tried to add duplicate address {address}")
        try:
            subprocess.run(f"ip addr add {address} dev lo", capture_output=True, check=True, shell=True)
        except subprocess.CalledProcessError as e:
            if e.stderr != b'RTNETLINK answers: File exists\n':
                raise ValueError(f"Couldn't add {address}")

        self.added_addresses.add(address)
