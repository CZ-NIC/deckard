"""Simple answer generator using local forwarder"""

import ipaddress

import answer_checker

d = {"SIMPLE_ANSWER" : answer_checker.make_query("good-a.test.knot-resolver.cz", "A"),
"EDNS_ANSWER" : answer_checker.make_query("good-a.test.knot-resolver.cz", "A", use_edns=0),
"DO_ANSWER" : answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True),
"CD_ANSWER" : answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True),
"RRSIG_ANSWER" : answer_checker.make_query("good-a.test.knot-resolver.cz", "A", want_dnssec=True),
"DNSKEY_ANSWER" : answer_checker.make_query("test.knot-resolver.cz", "DNSKEY", want_dnssec=True),
"DS_ANSWER" : answer_checker.make_query("cz", "DS", want_dnssec=True),
"NSEC_NEGATIVE_ANSWER" : answer_checker.make_query("nonexistent.nsec.test.knot-resolver.cz", "A", want_dnssec=True),
"NSEC3_NEGATIVE_ANSWER" : answer_checker.make_query("nonexistent.nsec3.test.knot-resolver.cz", "A", want_dnssec=True),
"UNKNOWN_TYPE_ANSWER" : answer_checker.make_query("weird-type.test.knot-resolver.cz", "TYPE20025"),
"NONEXISTENT_DS_DELEGATION_NSEC_ANSWER" : answer_checker.make_query("unsigned.nsec.test.knot-resolver.cz", "DS", want_dnssec=True),
"NONEXISTENT_DS_DELEGATION_NSEC3_ANSWER" : answer_checker.make_query("unsigned.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True),
"NONEXISTENT_DELEGATION_FROM_NSEC_ANSWER" : answer_checker.make_query("nonexistent.nsec.test.knot-resolver.cz", "DS", want_dnssec=True),
"NONEXISTENT_DELEGATION_FROM_NSEC3_ANSWER" : answer_checker.make_query("nonexistent.nsec3.test.knot-resolver.cz", "DS", want_dnssec=True),
"NONEXISTENT_TYPE_NSEC3_ANSWER" : answer_checker.make_query("nsec3.test.knot-resolver.cz", "TYPE65281", want_dnssec=True),
"NONEXISTENT_TYPE_NSEC_ANSWER" : answer_checker.make_query("nsec.test.knot-resolver.cz", "TYPE65281", want_dnssec=True)}

for k, v in d.items():
    print('%s = dns.message.from_text("""%s""")\n' % (k, answer_checker._string_answer(v, ipaddress.IPv4Address("127.0.0.1"))))
