"""
Take DNSKEYs from a zonefile and put info about them to a file

Command line arguments:
        test        path to zonefile
        -m MAP      path to a file where the keymap will be stored,
                    default is key_map in working directory
"""

import json
import os
import struct
import sys
import argparse
import logging
import dns
import dns.zone


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parseargs():
    """
    Parse arguments of the script

    Return:
        zone (str)      path to zonefile to take keys from
        storage(str)    path to a directory where the keymap will be stored,
                        default is working directory
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument("zone",
                           help="path to zonefile to take keys from")
    argparser.add_argument("-m", "--map",
                           help="""path to a file where the keymap will be stored,
                           default is key_map in working directory""",
                           default="key_map")
    args = argparser.parse_args()
    if os.path.isfile(args.zone):
        zone = args.zone
    else:
        logger.error("%s is not a file.")
        sys.exit(1)
    return zone, args.map


def get_dnskey_set(zonefile):
    """
    Get DNSKEY rdataset from zone

    Attributes:
        zone (str)      path to zonefile to take keys from

    Return:
        dns.rdataset.Rdataset   rdataset of DNSKEYs
    """
    zone = dns.zone.from_file(zonefile, zonefile.split("/")[-1][:-5], relativize=False)
    return zone.get_rdataset(zone.origin, dns.rdatatype.DNSKEY)


def key_tag(dnskey):
    """
    Given a dns.rdtypes.ANY.DNSKEY dnskey, compute and return its keytag.

    For details, see RFC 2535, section 4.1.6

    Attributes:
        dnskey (dns.rdtypes.ANY.DNSKEY)
    """
    if dnskey.algorithm == 1:
        a = ord(dnskey.key[-3]) << 8
        b = ord(dnskey.key[-2])
        return a + b
    else:
        header = struct.pack("!HBB", dnskey.flags, dnskey.protocol, dnskey.algorithm)
        key = header + dnskey.key
        ac = 0
        for i, value in enumerate(key):
            if i % 2:
                ac += value
            else:
                ac += (value << 8)
        ac += (ac >> 16) & 0xffff
        return ac & 0xffff


def unique_tags(keys):
    """
    Check if key tags of keys in zone are unique

    Attributes:
        keys (collection of dns.rdtypes.ANY.DNSKEY)

    Return:
        True if the tags are unique, False if not
    """
    tags = set()
    for key in keys:
        tags.add(key_tag(key))
    return len(tags) == len(keys)


def make_key_map(key_collection, map_path):
    """
    Put information about keys to a file

    Attributes:
        keys (collection of dns.rdtypes.ANY.DNSKEY)
        map_path (str)      path to the file
    """

    keys = []
    for key in key_collection:
        key_dict = {}
        key_dict["tag"] = key_tag(key)
        key_dict["algorithm"] = key.algorithm
        key_dict["flags"] = key.flags
        keys.append(key_dict)

    map_file = open(map_path, "w")
    json.dump(keys, map_file, indent=4, separators=(',', ': '))
    map_file.close()


def main():
    """
    Take DNSKEYs from a zonefile and put info about them to a file
    """
    zone, mapfile = parseargs()
    dnskeys = get_dnskey_set(zone)
    if not unique_tags(dnskeys):
        logger.error("UNSUPPORTED: Multiple keys with same tag.")
        sys.exit(1)
    make_key_map(dnskeys, mapfile)


main()
