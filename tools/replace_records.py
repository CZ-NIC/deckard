"""
Change records from zone in .rpl file
"""


import argparse
import json
import logging
import os
import sys
import dns
import dns.zone
import pydnstest.scenario
import pydnstest.augwrap
import keytag


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parseargs():
    """
    Parse arguments of the script

    Return:
        key_json (str)  path to file with mapping of old keys to new ones
        zone (str)      path to zonefile
        rpl (str)       path to .rpl test
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument("key_json",
                           help="path to file with mapping of old keys to new ones")
    argparser.add_argument("zone",
                           help="path to zonefile")
    argparser.add_argument("rpl",
                           help="path to .rpl test")
    args = argparser.parse_args()

    if not os.path.isfile(args.key_json):
        logger.error("%s is not a file.", args.key_json)
        sys.exit(1)
    if not os.path.isfile(args.zone):
        logger.error("%s is not a file.", args.zone)
        sys.exit(1)
    if not os.path.isfile(args.rpl):
        logger.error("%s is not a file.", args.rpl)
        sys.exit(1)
    if not args.zone.endswith(".zone.signed"):
        logger.error("%s does not have the standart signed zonefile name format.", args.zone)
    return args.key_json, args.zone, args.rpl


def parse_test(test):
    """ Parse the test

    Attributes:
        test (str)  path to .rpl file
    """
    load_path = os.path.dirname(__file__)
    if load_path:
        load_path += "/"
    load_path += "pydnstest"
    aug = pydnstest.augwrap.AugeasWrapper(confpath=os.path.realpath(test),
                                          lens='deckard',
                                          loadpath=load_path)
    return aug


def get_keys(key_json):
    """
    Transform list of dictionaries from json file to dictionary in form old_tag:new_tag
    """
    with open(key_json) as json_file:
        keys_from_json = json.load(json_file)
    return {key["old"]: key["new"] for key in keys_from_json}


def parse_zonefile(zonefile):
    """
    Get zone object from zonefile
    """
    origin = dns.name.from_text(zonefile.split("/")[-1][:-12])
    return dns.zone.from_file(zonefile, origin, relativize=False, check_origin=False)


def get_rrsig(owner, rrsig, keys, zone):
    """
    Find corresponding RRSIG from zone

    Attributes:
        owner (dns.name.Name)   owner of the RRSIG
        rrsig (dns.drtypes.ANY.RRSIG.RRSIG)
        keys                    mapping of old keytags to new ones
        zone                    zonefile with new records

    Return:
        new RRSIG data (str)
    """
    rdataset = zone.find_rdataset(owner, dns.rdatatype.RRSIG, covers=rrsig.covers())
    for new_rrsig in rdataset:
        if new_rrsig.key_tag == keys[rrsig.key_tag]:
            return new_rrsig.to_text()
    logger.error("Didn't find matching record to %s in the zone.", rrsig.to_text())
    sys.exit(1)


def get_dnskey(owner, dnskey, keys, zone):
    """
    Find corresponding DNSKEY from zone

    Attributes:
        owner (dns.name.Name)   owner of the DNSKEY
        dnskey (dns.drtypes.ANY.DNESKEY.DNSKEY)
        keys                    mapping of old keytags to new ones
        zone                    zonefile with new records

    Return:
        new DNSKEY data (str)
    """
    rdataset = zone.find_rdataset(owner, dns.rdatatype.DNSKEY)
    for new_dnskey in rdataset:
        if keytag.from_dnskey(new_dnskey) == keys[keytag.from_dnskey(dnskey)]:
            return new_dnskey.to_text()
    logger.error("Didn't find matching record to %s in the zone.", dnskey.to_text())
    sys.exit(1)


def get_ds(owner, ds, keys, zone):
    """
    Find corresponding DNSKEY from zone

    Attributes:
        owner (dns.name.Name)   owner of the DS
        ds          (dns.drtypes.ANY.DS.DS)
        keys        mapping of old keytags to new ones
        zone        zonefile with new records

    Return:
        new DS data (str)
    """
    rdataset = zone.find_rdataset(owner, dns.rdatatype.DS)
    for new_ds in rdataset:
        if new_ds.key_tag == keys[ds.key_tag] and new_ds.digest_type == ds.digest_type:
            return new_ds.to_text()
    logger.error("Didn't find matching record to %s in the zone.", ds.to_text())
    sys.exit(1)


def replace_in_augtree(tree, keys, zone):
    """
    Replace RRSIG, DNSKEY and DS records with new ones from a zone

    Attributes:
        tree                Augeas tree
        keys ({int:int})    mapping of old keytags to new ones
        zone (dns.zone.Zone)
    """
    for entry in tree.match("/scenario/range/entry"):
        records = list(entry.match("/section/answer/record"))
        records.extend(list(entry.match("/section/authority/record")))
        records.extend(list(entry.match("/section/additional/record")))

        for record in records:
            rdata = dns.rdata.from_text(dns.rdataclass.from_text(record["/class"].value),
                                        dns.rdatatype.from_text(record["/type"].value),
                                        record["/data"].value)
            owner = dns.name.from_text(record["/domain"].value)
            if rdata.rdtype == dns.rdatatype.RRSIG:
                record["/data"].value = get_rrsig(owner, rdata, keys, zone)
            if rdata.rdtype == dns.rdatatype.DNSKEY:
                record["/data"].value = get_dnskey(owner, rdata, keys, zone)
            if rdata.rdtype == dns.rdatatype.DS:
                record["/data"].value = get_dnskey(owner, rdata, keys, zone)


def main():
    """
    Change records from zone in .rpl file
    """
    key_json, zonefile, rpl = parseargs()
    aug = parse_test(rpl)
    keys = get_keys(key_json)
    zone = parse_zonefile(zonefile)
    replace_in_augtree(aug.tree, keys, zone)
    aug.save()


main()
