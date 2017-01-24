#!/usr/bin/python
# parse pcap specified as $1 and print found RR . DNSKEY SEP
# Example output:
# . IN DNSKEY 257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0 EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/Q Zxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hO A2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8 ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=

import codecs
import subprocess
import sys

base_cmd=["tshark",
          "-r", sys.argv[1],
          "-Y", "dns.qry.name.len == 0 and dns.qry.type == 48 and dns.flags.response == 1 and dns.dnskey.flags.secure_entry_point == 1",
          "-T", "fields",
          "-E", "occurrence=f",
          "-e", "dns.dnskey.flags",
          "-e", "dns.dnskey.protocol",
          "-e", "dns.dnskey.algorithm",
          "-e", "dns.dnskey.public_key"
         ]
flags_hex, protocol, algo, pk_hex = subprocess.check_output(base_cmd).split()

# convert data into standardized RR format
flags = int(flags_hex, base=16)

pk_hex = pk_hex.replace(":", "")
pk_bin = codecs.decode(pk_hex, "hex")
pk_b64 = codecs.encode(pk_bin, "base64").replace("\n", " ").strip()
print(". IN DNSKEY {0} {1} {2} {3}".format(flags, protocol, algo, pk_b64))
#echo ". IN DNSKEY $FLAGS $PROTOCOL $ALGO $PK"
