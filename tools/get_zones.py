import argparse
import logging
import os
import sys
import dns
import dns.zone
import pydnstest.scenario
import pydnstest.augwrap


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_test(test):
    """ Parse the test """
    _, config = pydnstest.scenario.parse_file(os.path.realpath(test))
    load_path = os.path.dirname(__file__)
    if load_path:
        load_path += "/"
    load_path += "pydnstest"
    aug = pydnstest.augwrap.AugeasWrapper(confpath=os.path.realpath(test),
                                          lens='deckard',
                                          loadpath=load_path)

    node = aug.tree
    return config, node


def add_record_to_zone(zones, zone_name, added_record):
    """
    Add a record from test to a zone

    Attributes:
        zone_name (str)    zone name
        added_record (str) augeas record node
    """
    if zone_name not in zones:
        zones[zone_name] = dns.zone.Zone(origin=zone_name)
    rdtype = dns.rdatatype.from_text(added_record["/type"].value)
    domain = added_record["/domain"].value
    rdclass = dns.rdataclass.from_text(added_record["/class"].value)
    rdata = dns.rdata.from_text(rdclass, rdtype, added_record["/data"].value)
    dataset = zones[zone_name].get_rdataset(domain, rdtype, create=True)
    dataset.add(rdata)

def add_all_from_entry(entry, zones):
    records = list(entry.match("/section/answer/record"))
    records.extend(list(entry.match("/section/authority/record")))
    records.extend(list(entry.match("/section/additional/record")))

    for record in records:
        if record["/type"].value == "RRSIG": #TODO: duplicity
            rrsig = dns.rdata.from_text(dns.rdataclass.from_text(record["/class"].value), dns.rdatatype.from_text(record["/type"].value), record["/data"].value)
            rrsig_data = record["/data"].value.split()
            signer = rrsig.signer.to_text()
            add_record_to_zone(zones, signer, record)

            covered_type = dns.rdatatype.to_text(rrsig.type_covered)
            covered_domain = record["/domain"].value
            for record2 in records:
                if (record2["/type"].value == covered_type
                        and record2["/domain"].value == covered_domain):
                    add_record_to_zone(zones, signer, record2)


def add_default_to_zone(zone, domain, rrtype, rdclass):
    """
    Add a record of given type to a zone

    Attributes:
        zone_name (str) zone name
        rrtype (str)    rrtype
    """
    default_data = {
        dns.rdatatype.A: "1.1.1.1",
        dns.rdatatype.AAAA: "1:1:1:1",
        dns.rdatatype.AFSDB: "1 record.added.for.resign.",
        dns.rdatatype.APL: "1:192.168.32.0/21 !1:192.168.38.0/28",
        dns.rdatatype.CAA: "0 issue record.added.for.resign.",
        dns.rdatatype.CDNSKEY: "256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3" +
                               "Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajI" +
                               "QKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmM" +
                               "Hfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL74" +
                               "2iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==  )",
        dns.rdatatype.CDS: "60485 5 1 ( added0added0added0added0added0added00000 )",
        dns.rdatatype.CERT: "DPKIX 1 SHA256 KR1L0GbocaIOOim1+qdHtOSrDcOsGiI2NCcxuX2/Tqc",
        dns.rdatatype.CNAME: "record.added.for.resign.",
        dns.rdatatype.DHCID: "( AAIBY2/AuCccgoJbsaxcQc9TUapptP69l" +
                             "OjxfNuVAA2kjEA= )",
        dns.rdatatype.DLV: "60485 5 1 ( added0added0added0added0added0added00000 )",
        dns.rdatatype.DNAME: "record.added.for.resign.",
        dns.rdatatype.DNSKEY: "256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3" +
                              "Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajI" +
                              "QKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmM" +
                              "Hfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL74" +
                              "2iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==  )",
        dns.rdatatype.DS: "60485 5 1 ( added0added0added0added0added0added00000 )",
        dns.rdatatype.EUI48: "AD-DE-D1-AD-DE-D1",
        dns.rdatatype.EUI64: "AD-DE-D1-AD-DE-D1-AD-D1",
        dns.rdatatype.HINFO: "ALTO ELF",
        dns.rdatatype.HIP: "( 2 200100107B1A74DF365639CC39F1D578 " +
                           "AwEAAbdxyhNuSutc5EMzxTs9LBPCIkOFH8cIvM4p9+LrV4e19" +
                           "WzK00+CI6zBCQTdtWsuxKbWIy87UOoJTwkUs7lBu+Upr1gsNr" +
                           "ut79ryra+bSRGQb1slImA8YVJyuIDsj7kwzG7jnERNqnWxZ48" +
                           "AWkskmdHaVDP4BcelrTI3rMXdXF5D )",
        dns.rdatatype.IPSECKEY: "( 10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt" +
                                "4AQ== )",
        dns.rdatatype.KX: "1 record.added.for.resign.",
        dns.rdatatype.LOC: "42 21 54 N 71 06 18 W -24m 30m",
        dns.rdatatype.MX: "1 record.added.for.resign.",
        dns.rdatatype.NAPTR: '100  50  "a"    "z3950+N2L+N2C"     ""   record.added.for.resign.',
        dns.rdatatype.NS: "record.added.for.resign.",
        # "NSEC":
        # "NSEC3":
        # "NSEC3PARAM":
        dns.rdatatype.PTR: "record.added.for.resign.",
        dns.rdatatype.RP: "record.added.for.resign. record.added.for.resign.",
        dns.rdatatype.RRSIG: "A 10 3 3600 20251231235959 20160308093040 2843 example.com. VSq+Dk" +
                             "xJYr9Z+uh3KgpyPNwtuim4WVXnTdhRW7HX90CP5tyOVjDDTehA UmCxB8iFjUFE3hl" +
                             "wDx0Y71g+8Oso1t0JGkvDtWf5RDx1w+4K/1pQ2JMGlZTh7juaGJzXtltxqBoY67z1F" +
                             "Bp9MI59O0hkABtz1CElj9LrhDr9wQa4 OUo=",
        dns.rdatatype.SOA: "record.added.for.resign. b. 1 2 3 4 3600",
        dns.rdatatype.SRV: "1 1 1 record.added.for.resign.",
        dns.rdatatype.SSHFP: "2 1 added0added0added0added0added0added0000",
        dns.rdatatype.TLSA: "( 0 0 1 added0added0added0added0added000 " +
                            "added0added0added0added0added000 )",
        dns.rdatatype.TXT: "\"Record added for resign\"",
        dns.rdatatype.URI: "10 1 \"record.added.for.resign.\""
    }

    if isinstance(rdclass, str):
        rdclass = dns.rdataclass.from_text(rdclass)
    rdata = dns.rdata.from_text(rdclass, rrtype, default_data[rrtype])
    dataset = zone.get_rdataset(domain, rrtype, create=True)
    dataset.add(rdata)


def add_signed(zone, name, rdataset):
    """
    Add some record of the type which is covered by a RRSIG if it is not in the test

    Attributes:
        zone(dns.zone.Zone)             zone with the RRSIG
        name(str)                       owner of the RRSIG
        rdataset(dns.rdataset.Rdataset) RRSIG rdataset
    """
    rdclass = rdataset.rdclass
    for rdata in rdataset.items:
        type_covered = rdata.covers()
        if zone.get_rdataset(name, type_covered) is None:
            add_default_to_zone(zone, name, type_covered, rdclass)


def types_from_nsec(nsec):
    types = []
    for (window, bitmap) in nsec.windows:
        for i in range(0, len(bitmap)):
            byte = bitmap[i]
            for j in range(0, 8):
                if byte & (0x80 >> j):
                    types.append(window * 256 + i * 8 + j)
    return types

def add_from_nsec(zone, name, rdataset):
    """
    Add some record of the type which is mentioned in NSEC if it is not in the test

    Attributes:
        zone(dns.zone.Zone)             zone with the NSEC
        name(str)                       owner of the NSEC
        rdataset(dns.rdataset.Rdataset) NSEC rdataset
    """

    rdclass = rdataset.rdclass
    for rdata in rdataset.items:
        covered_types = types_from_nsec(rdata)
        for rrtype in covered_types:
            if zone.get_rdataset(name, rrtype) is None:
                add_default_to_zone(zone, name, rrtype, rdclass)
                

        if zone.get_node(rdata.next) is None:
            add_default_to_zone(zone, rdata.next, dns.rdatatype.TXT, rdclass)


def add_if_is_not_in_zone(zone, rdtype):
    """
    Add a record to the zone if it is missing

    """
    if zone.get_rdataset(zone.origin, rdtype) is None:
        add_default_to_zone(zone, zone.origin, rdtype, zone.rdclass)


def zonefiles_from_rpl(rpl, directory):
    """
    Create zonefiles used in test

    Attributes:
        rpl (str)       path to a .rpl file
        directory (str) path to the directory where the zonefiles will be stored
    """


    # Parse test
    _, node = parse_test(rpl)

    zones = {}
    for entry in node.match("/scenario/range/entry"):
        add_all_from_entry(entry, zones)

    for zone in zones.values():
        for name in zone:
            node = zone[name]
            for rdataset in node:
                if rdataset.rdtype == dns.rdatatype.RRSIG:
                    add_signed(zone, name, rdataset)
                if rdataset.rdtype == dns.rdatatype.NSEC:
                    add_from_nsec(zone, name, rdataset)
        add_if_is_not_in_zone(zone, dns.rdatatype.SOA)
        add_if_is_not_in_zone(zone, dns.rdatatype.NS)

    for zone in zones.values():
        filename = zone.origin.to_text()
        zone.to_file(directory + "/" + filename + ".zone", relativize=False)


def parseargs():
    """
    Parse arguments of the script

    Return:
        test (str)      path to test file to take zones from
        storage(str)    directory where the zones will be stored
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument("test",
                           help="path to .rpl test to make zones from")
    argparser.add_argument("-s", "--storage",
                           help="directory where the zones will be stored", default=".")
    args = argparser.parse_args()
    if os.path.isfile(args.test):
        test = args.test
    else:
        logger.error("%s is not a file.")
        sys.exit(1)
    return test, args.storage


def main():
    test, storage = parseargs()
    if not os.path.exists(storage):
        os.makedirs(storage)
    zonefiles_from_rpl(test, storage)

main()
