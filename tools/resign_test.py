"""
Resign .rpl tests

Dependencies: dnssec-keygen, dnssec-signzone

Usage: resign_test.py [-h] [-s] [-k KEYS [KEYS ...]] tests

positional arguments:
  tests                 .rpl test or a directory of tests to resign

optional arguments:
  -h, --help            show this help message and exit
  -s, --store           store files (keys, zonefiles, dssets)
  -k KEYS [KEYS ...], --keys KEYS [KEYS ...]
                        files with original keys used in the test you want to
                        use again
"""

import os
import sys
import subprocess
import fileinput
import time
import argparse
import struct
import shutil
import dns
import pydnstest.scenario
import pydnstest.augwrap


class ZoneRecord:
    """
    Represenatin of a DNS record

    All attributes are strings
    """

    def __init__(self, domain, ttl, dns_class, rrtype, data):
        self.domain = domain
        self.ttl = ttl
        self.dns_class = dns_class
        self.rrtype = rrtype
        self.data = data

    def __str__(self):
        return self.domain + "\t" + self.ttl + "\t"\
            + self.dns_class + "\t" + self.rrtype + "\t" + self.data

    def __eq__(self, other):
        return (self.domain == other.domain and
                self.ttl == other.ttl and
                self.dns_class == other.dns_class and
                self.rrtype == other.rrtype and
                self.data == other.data)

    def __hash__(self):
        return hash((self.domain, self.rrtype, self.dns_class, self.data))


class Key:
    """
    Represenatin of a DNS record

    Attributes:
        algorithm (int) The algorithm used for the key
        tag (str)       The key tag
        domain (str)    Domain the key belongs to
        flags (int)     The key flags
        zone_records(list of ZoneRecords)
                        Records signed by this key
        newkeytag (str) Tag of the key replacing this one
        filename (str)  File with the key replacing this one
        origkey (str)   The original key
        newkey (str)    The replacing key
    """

    def __init__(self, key, tag, domain, origstring):
        """
        Initialize Key object

        Parameters:
            key (dns.rdtypes.ANY.DNSKEY)
            tag (str)           The key tag
            domain (str)        Domain the key belongs to
            origstring (str)    The original key
        """
        self.algorithm = key.algorithm
        self.tag = tag
        self.domain = domain
        self.flags = key.flags
        self.zone_records = []
        self.newkeytag = ""
        self.filename = ""
        self.origkey = origstring
        self.newkey = ""

    def generate_new_key(self, exist_keys):
        """
        If the key is not in exist_keys, generate a new key with the same
        algortithm, flags and domain as self using dnssec-keygen.

        Sets self.filename - name of the keyfile
             self.newkeytag - tag of the key.
        """

        # Save existing key
        if exist_keys:
            for key in exist_keys:
                tag = key.split('+')[-1][:-4]
                if int(tag) == int(self.tag):
                    self.newkeytag = tag
                    self.filename = key
                    return

        # Create new key
        command = "dnssec-keygen "
        if self.flags == 257:
            command += "-f ksk "
        if not os.path.isdir("resign"):
            os.mkdir("resign")
        command += "-K resign -a " + str(self.algorithm) + " -b 1024 -n ZONE " +\
            self.domain + " 2>/dev/null"
        self.filename = subprocess.check_output(command, shell=True).decode("utf-8")
        self.filename = self.filename[:-1]
        self.newkeytag = self.filename.split("+")[-1]
        self.filename = "resign/" + self.filename + ".key"


class ReplacedSignature:
    def __init__(self, domain, key, rrtype, original):
        self.domain = domain
        self.rrtype = rrtype
        self.key = key
        self.original = original
        self.new = ""


class ReplacedDS:
    def __init__(self, domain, original):
        self.domain = domain
        self.original = original
        self.new = ""


class Zone:
    def __init__(self, key):
        self.domain = key.domain
        self.records = key.zone_records
        self.keyfiles = [key.filename]
        self.signed = False

    def addkey(self, key):
        """
        Add another key to existing zone
        """
        self.records = self.records + key.zone_records
        self.keyfiles.append(key.filename)

    def create_file(self):
        """
        Create zonefile with all records in self.records and include
        keys from self.keyfiles.
        """
        self.records = list(set(self.records))
        if not check_soa(self.records):
            # Add SOA record
            self.records.append(ZoneRecord(self.domain, "3600", "IN",
                                           "SOA", "a. b. 1 2 3 4 3600"))

        # Create zonefile
        file = open("resign/" + self.domain + ".zone", "w")
        for record in self.records:
            file.write(str(record) + "\n")

        # Include keys
        for key in self.keyfiles:
            file.write("$INCLUDE " + key + "\n")
        file.close()

    def sign(self):
        """
        Sign the zonefile with dnssec-signzone

        Return:
            True for success, False otherwise.
        """
        if os.system("dnssec-signzone -z -N INCREMENT -O full -P -K resign -d resign -o " +
                     self.domain + " resign/" + self.domain + ".zone") != 0:
            print("Error: Cannot sign zone " + self.domain)
            return False

        self.signed = True
        return True


def key_tag(dnskey):
    """
    Given a dns.rdtypes.ANY.DNSKEY dnskey, compute and return its keytag.

    For details, see RFC 2535, section 4.1.6
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
        return str(ac & 0xffff)


def check_soa(records):
    """
    Check if there is a SOA record in the list of zone records
    """
    for record in records:
        if record.rrtype == "SOA":
            return True
    return False


def parse_test(test):
    """ Parse the test """
    _, config = pydnstest.scenario.parse_file(os.path.realpath(test))
    aug = pydnstest.augwrap.AugeasWrapper(confpath=os.path.realpath(test),
                                          lens='Deckard', loadpath="pydnstest")
    node = aug.tree
    return config, node


def find_keys(node):
    """ Find all the keys used in the test."""
    keys = {}
    for entry in node.match("/scenario/range/entry"):
        records = list(entry.match("/section/answer/record"))
        records.extend(list(entry.match("/section/authority/record")))
        records.extend(list(entry.match("/section/additional/record")))

        for record in records:
            if record["/type"].value == "DNSKEY":
                dnskey = dns.rrset.from_text(record["/domain"].value, 300, 1, dns.rdatatype.DNSKEY,
                                             record["/data"].value)  # TTL, class are not important
                keytag = key_tag(dnskey.items[0])
                keyindex = keytag + record["/domain"].value
                keys[keyindex] = Key(dnskey.items[0], keytag,
                                     record["/domain"].value, record["/data"].value)
    return keys


def read_rrsig(record, records, keys):
    """ Get data from the RRSIG record and the record signed by it."""
    rrsig_data = record["/data"].value.split()
    keytag = rrsig_data[6]
    zone_name = rrsig_data[7]
    domain = record["/domain"].value
    rrtype = rrsig_data[0]
    rrsig = None
    signed_record = None
    for record2 in records:
        if (record2["/domain"].value == domain and
                record2["/type"].value == rrtype):
            dns_class = record2["/class"].value
            try:
                ttl = record2["/ttl"].value
            except KeyError:
                ttl = "3600"
            rrsig = ReplacedSignature(domain, keys[keytag + zone_name],
                                      rrtype, record["/data"].value)
            signed_record = ZoneRecord(domain, ttl, dns_class, rrtype, record2["/data"].value)
            break
    return rrsig, signed_record, keytag, zone_name


def find_trust_anchors(config):
    """
    Find trust anchors.

    Retrun:
        trust_anchors   List of trust anchor strings
        replaced_dss    List of ReplacedDS objects representing all DSs
                        used in trust anchors.
    """
    replaced_dss = []
    trust_anchors = []
    for line in config:
        if line[0] == "trust-anchor":
            trust_anchor = line[1]
            if trust_anchor[0] == "\"":
                trust_anchor = trust_anchor[1:-1]
            try:
                ds_index = trust_anchor.split().index("DS")
                ta_split = trust_anchor.split(maxsplit=ds_index + 1)
                replaced_dss.append(ReplacedDS(ta_split[0],
                                               ta_split[ds_index + 1]))
            except ValueError:
                pass
            trust_anchors.append(trust_anchor)
    return trust_anchors, replaced_dss


def find_signed_records(node, keys):
    """
    Find all signed records and DSs.

    Return:
        keys            List of Key objects. In attribute zone_records
                        are records signed by the key.
        replaced_rrsigs List of ReplacedSignature objects representing
                        all RRSIGs used in the test.
        replaced_dss    List of ReplacedDS objects representing all DSs
                        used in the test scenario.
    """
    replaced_rrsigs = []
    replaced_dss = []

    for entry in node.match("/scenario/range/entry"):
        records = list(entry.match("/section/answer/record"))
        records.extend(list(entry.match("/section/authority/record")))
        records.extend(list(entry.match("/section/additional/record")))

        for record in records:
            if record["/type"].value == "RRSIG":
                rrsig, signed_record, keytag, zone_name = read_rrsig(record, records, keys)
                if signed_record is None:

                    print("Error: RRSIG of unknown record.")
                    sys.exit(1)
                if signed_record.rrtype not in ("DNSKEY", "NSEC"):
                    try:
                        keyindex = keytag + zone_name
                        keys[keyindex].zone_records.append(signed_record)
                    except KeyError:
                        print("Error:", signed_record,
                              "signed by unknown key", keytag)
                        sys.exit(1)
                replaced_rrsigs.append(rrsig)
            if record["/type"].value == "DS":
                replaced_dss.append(ReplacedDS(record["/domain"].value,
                                               record["/data"].value))
    return keys, replaced_rrsigs, replaced_dss


def make_zones(keys):
    """ Make list od Zone objects representing zones in the test."""
    zones = {}
    for key in keys:
        if key.domain in zones:
            zones[key.domain].addkey(key)
        else:
            zones[key.domain] = Zone(key)
    return zones


def sign_zone_tree(top, zones):
    """Recursively sign a tree of zones"""
    try:
        zone = zones[top]
    except KeyError:
        return True
    if zone.signed:
        return True
    for record in zone.records:
        record.new = ""
        if record.rrtype == "DS":
            sign_zone_tree(record.domain, zones)
            zone.records.append(ZoneRecord(record.domain, "300", "IN", "NS", "ns.fict.cz"))
            dsset = open("resign/dsset-" + record.domain)
            for line in dsset:
                if record.data.split()[2] == line.split()[5]:
                    # TODO: Nevím, co se tady děje, pořebuju najít test s vnořenými zónami
                    record.data = line.split(maxsplit=3)[3]
    zone.create_file()
    return zone.sign()


def get_new_records(signed_zonefile, dssetfile, replaced_rrsigs,
                    replaced_dss, zone_name, keys):
    """
    Read new records from signed zonefile and match them
    to the old records from the test
    """
    
    # Get records from the zonefile
    zonefile = open(signed_zonefile, "r")
    for line in zonefile:
        line = line.split()
        if line[0][0] != ";":
            try:
                rrsig_index = line.index("RRSIG")
                if rrsig_index <= 3:  # RRSIG is the record type
                    for rrsig in replaced_rrsigs:
                        if (line[0] == rrsig.domain and line[rrsig_index + 1] == rrsig.rrtype and
                                int(line[rrsig_index + 7]) == int(rrsig.key.newkeytag)):
                            new = ""
                            for word in line[rrsig_index + 1:]:
                                new += word + " "
                            rrsig.new = new
                    continue
            except ValueError:
                pass
            try:
                ds_index = line.index("DS")
                if ds_index <= 3:  # DS is the record type
                    for record in replaced_dss:
                        if line[0] == record.domain:
                            new = ""
                            for word in line[ds_index + 1:]:
                                new += word + " "
                        record.new = new
                    continue
            except ValueError:
                pass
            try:
                dnskey_index = line.index("DNSKEY")
                if dnskey_index <= 3:  # DNSKEY is the record type
                    data = ""
                    for word in line[dnskey_index + 1:]:
                        data += word + " "
                    dnskey = dns.rrset.from_text(line[0], 300, 1,
                                                 dns.rdatatype.DNSKEY, data)
                    keytag = key_tag(dnskey.items[0])
                    for key in keys.values():
                        if int(keytag) == int(key.newkeytag):
                            key.newkey = data
                    continue
            except ValueError:
                pass
    zonefile.close()
    
    # Get DS record from dsset file
    dsset = open(dssetfile, "r")
    lines = dsset.readlines()
    for record in replaced_dss:
        for line in lines:
            split_line = line.split()
            if (record.domain == zone_name and
                    record.original.split()[2] == split_line[5]):
                record.new = ""
                for word in split_line[3:]:
                    record.new += word + " "
    dsset.close()
    return replaced_rrsigs, replaced_dss


def replace(test, replaced_rrsigs, replaced_dss, keys):
    """ Replace all changed data in the test file. """
    errmsg = ""
    with fileinput.FileInput(test, inplace=True, backup='.bak') as file:
        for line in file:
            try:
                # Change test timestamp to actual time
                if line.split()[0] == "val-override-date:":
                    line = "val-override-date: \"" +\
                        time.strftime("%Y%m%d%H%M%S") + "\"\n"

                # Replace RRSIGs
                elif "RRSIG" in line.split():
                    for rrsig in replaced_rrsigs:
                        if rrsig.original in line:
                            if rrsig.new == "":
                                errmsg += "Warning: new RRSIG of "
                                errmsg += rrsig.domain + " " + rrsig.rrtype
                                errmsg += " is empty\n"
                            line = line.replace(rrsig.original, rrsig.new)

                # Replace DSs
                elif "DS" in line.split():
                    for record in replaced_dss:
                        if record.original in line:
                            if record.new == "":
                                errmsg += "Warning: cannot find new DS of "
                                errmsg += record.domain + ", not changing\n" # This happens when there is a trust anchor which does not sign anythinthing
                            else:
                                line = line.replace(record.original, record.new)

                # Replace DNSKEYSs
                elif "DNSKEY" in line.split():
                    for key in keys.values():
                        if key.origkey in line:
                            if key.newkey == "":
                                errmsg += "Warning: new DNSKEY of "
                                errmsg += key.domain + " is empty\n"
                            line = line.replace(key.origkey, key.newkey)
            except IndexError:
                pass
            print(line, end="")
    if errmsg:
        print(errmsg)


def resign_test(test, exist_keys):
    """
    Resign one test. If possible, use keys existing keys

    Params:
        test (str)                  file with the test
        exist_keys (list of str)    tags of existing keys

    Return:
        True for success, False otherwise.
    """
    # Copy original keys to working directory
    copykeys(exist_keys)
    
    # Parse test
    config, node = parse_test(test)

    # Find keys and records to be changed
    keys = find_keys(node)
    trust_anchors, replaced_dss = find_trust_anchors(config)
    keys, replaced_rrsigs, scen_replaced_dss =\
        find_signed_records(node, keys)
    replaced_dss = replaced_dss + scen_replaced_dss

    # Find zones from trust anchor - roots of the signing trees
    trust_anchor_zones = []
    for anchor in trust_anchors:
        trust_anchor_zones.append(anchor.split()[0])

    # Generate new keys
    for key in keys.values():
        key.generate_new_key(exist_keys)

    # Make zone files
    zones = make_zones(keys.values())

    # Sign zones
    for anchor_zone in trust_anchor_zones:
        if not sign_zone_tree(anchor_zone, zones):
            print("Error: Cannot sign zone", zones[anchor_zone].domain)
            return False

    # Replace keys and signatures in tests
    for zone in zones.values():
        replaced_rrsigs, replaced_dss =\
            get_new_records("resign/" + zone.domain + ".zone.signed",
                            "resign/dsset-" + zone.domain, replaced_rrsigs,
                            replaced_dss, zone.domain, keys)
    replace(test, replaced_rrsigs, replaced_dss, keys)
    return True


def getkeys(keyfiles):
    keys = []
    for keyfile in keyfiles:
        if len(keyfile) < 5 or keyfile[-4:] != ".key":
            print(keyfile, "is not .key file, skipping key.")
            continue
        if not os.path.isfile(keyfile[:-4] + ".private"):
            print("Cannot find", keyfile[:-4] + ".private,", "skipping key.")
            continue
        keys.append(keyfile)
    return keys


def copykeys(keyfiles):
    """ Copy key files to folder resign/ """
    if not os.path.isdir("resign"):
        os.mkdir("resign")
    for keyfile in keyfiles:
        shutil.copyfile(keyfile, "resign/" + os.path.basename(keyfile))
        shutil.copyfile(keyfile[:-4] + ".private", "resign/" +
                        os.path.basename(keyfile)[:-4] + ".private")


def check_depedencies():
    """ End script if needed programmes ase not installed """
    if shutil.which("dnssec-keygen") is None:
        print("Error: Missing program dnssec-keygen.")
        sys.exit(1)
    if shutil.which("dnssec-signzone") is None:
        print("Error: Missing program dnssec-signzone.")
        sys.exit(1)


def parseargs():
    """
    Parse arguments of the script

    Return:
        tests (list of str) test files to be resigned
        origkeytags         tags of keys to be used
        store (bool)        true if auxiliary files should be stored
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument("tests",
                           help=".rpl test or a directory of tests to resign")
    argparser.add_argument("-s", "--store",
                           help="store files (keys, zonefiles, dssets)",
                           action="store_true")
    argparser.add_argument("-k", "--keys",
                           help="files with original keys used in the test you want to use again",
                           nargs="+")
    args = argparser.parse_args()
    if os.path.isfile(args.tests):
        tests = [args.tests]
    elif os.path.isdir(args.tests):
        tests = os.listdir(args.tests)
        for i, test in enumerate(tests):
            tests[i] = args.tests + "/" + test
        print(tests)
    else:
        print("Error:", args.tests, "is not a file or directory.")
        sys.exit(1)
    origkeys = []
    if args.keys:
        origkeys = getkeys(args.keys)
    return tests, origkeys, args.store


def clean(test, store):
    """
    Deal with auxiliary files (keys, zonefiles etc. according to store parameter.

    If store is true, move all files made for the resigninig to folder of the test.
    If store is false, delete them.
    """
    if store:
        testdir = "resign/" + test.split("/")[-1][:-4]
        if not os.path.isdir(testdir):  # Create folder with the name of the test
            os.mkdir(testdir)
        for filename in os.listdir("resign"):   # Move files
            if os.path.isfile("resign/" + filename):
                os.rename("resign/" + filename, testdir + "/" +
                          filename)
    else:
        for filename in os.listdir("resign"):   # Remove files
            if os.path.isfile("resign/" + filename):
                os.remove("resign/" + filename)
        try:
            os.rmdir("resign")
        except OSError:
            pass


def main():
    """ Resign .rpl tests. """
    check_depedencies()
    tests, origkeys, store = parseargs()
    for test in tests:
        if test[-4:] != ".rpl":
            print(test, "is not a .rpl file, skipping.")
        else:
            print("Resigning", test)
            success = resign_test(test, origkeys)
        clean(test, store)
        if(not success):
            print("Error")
            sys.exit(1)


main()


# TODO: Případy, kde nefunguje
#   - NSEC3 (např. val_deleg_nons.rpl)
#   - NSEC obahuje záznamy, které samotné v testu nejsou (např. val_ad_qtype_ds.rpl)
#   - RRSIG záznamu, který samotný v testu není (např. val_cname_oob.rpl)
#   - upravené podpisy (např. val_cname_new_signer.rpl, val_minimal*.rpl)
#   - ...
