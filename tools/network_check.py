"""Test suite to determine conditions of current network in regards to DNS(SEC) traffic.
Invoke with `python3 -m pytest network_check.py`. """
# pylint: disable=C0301,C0111
# flake8: noqa
import ipaddress
import pytest

import dns.message

import answer_checker

# These are IPs of master-dns.labs.nic.cz
AUTHORITATIVE_SERVERS = [ipaddress.IPv4Address("217.31.192.131"), ipaddress.IPv6Address("2001:1488:ac15:ff90::131")]
ALL = {"opcode", "qtype", "qname", "flags", "rcode", "answer", "authority", "additional"}

VERSION_QUERY = dns.message.make_query("_version.test.knot-resolver.cz", "TXT")
VERSION_ANSWER = dns.message.from_text("""id 29633
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
_version.test.knot-resolver.cz. IN TXT
;ANSWER
_version.test.knot-resolver.cz. 3600 IN TXT "1"
;AUTHORITY
;ADDITIONAL
""")


@pytest.mark.parametrize("server", AUTHORITATIVE_SERVERS)
def test_zone_version(server):
    return answer_checker.send_and_check(VERSION_QUERY,
                                         VERSION_ANSWER,
                                         server,
                                         ALL - {"flags"})


QUERY = answer_checker.make_query("test.knot-resolver.cz", "A", want_dnssec=True, payload=4096)
ANSWER = dns.message.from_text("""id 30776
opcode QUERY
rcode NOERROR
flags QR AA RD
edns 0
eflags DO
payload 4096
;QUESTION
test.knot-resolver.cz. IN A
;ANSWER
test.knot-resolver.cz. 3600 IN A 217.31.192.130
test.knot-resolver.cz. 3600 IN RRSIG A 13 3 3600 20370119135450 20190205122450 58 test.knot-resolver.cz. G9DTWRE8QKe0MKyHn+PZcgf+ggIR9Sk+ E9qtd8IlpEt3+y28qPp0lgDQojpQL9sv lqgC0g5e2ZIsZWg1T5ICNQ==
;AUTHORITY
;ADDITIONAL
""")


@pytest.mark.parametrize("server", AUTHORITATIVE_SERVERS)
def test_remote_udp_53(server):
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         server,
                                         ALL)


@pytest.mark.parametrize("server", AUTHORITATIVE_SERVERS)
def test_remote_tcp_53(server):
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         server,
                                         ALL,
                                         tcp=True)


LONG_QUERY = answer_checker.make_query("test.knot-resolver.cz", "TXT", use_edns=0, payload=4096, want_dnssec=True)
LONG_ANSWER = dns.message.from_text("""id 17570
opcode QUERY
rcode NOERROR
flags QR AA RD
edns 0
payload 4096
;QUESTION
test.knot-resolver.cz. IN TXT
;ANSWER
test.knot-resolver.cz. 3600 IN TXT "Davku ve me o pln uvitani stari s tvuj neda? Tik kufr u traslo uf tabuli znaky mesity bimbal vyrvat vydelal pobezi zahajil a tajnosti. By 77 dusic ach prazdna kasari k zac platne potiz. O hon 30 otazek jiz post i rad zeleninu vyhrknu bhutanu nezdalo. I tr" "ida, ptat lzes vypadla newton, utal hm je bas samymi u sobe ukaz kazne medove u placeny ke ah jo zpola o ocich. Sul trimesicni kontrolujte v predstirana po nej mit za devetadevadesati eh mi lezu slava vuz v me smery. Tri akt dlazbu dal lamu, kavkam on zas" "luhy, sad muzikant vek. Paty neme radili trunil docist tech obou zari. My ze 11 tlusti jsemvidel. Podivej i prs kralik at ted o vynahradit ti si ma charakterni nehybny tulak poskytl rad! Muz ztuhla, ci ah propatral misce! Slz eh at? Zenou dilo intuici. Le" "su pud povesti, i jamou tej. V az vdanou zrejmo za ctil 81 kolika u ustrnule malicherny holemi nekradla jinych morfia: pocasi poplaseny zpovidat az dne vyjimecna zidovskem stejny sluzek tajemny hlidat u ruzovym pry jestli vyslychalo zem nerozbrecte farare" " strhla v mem tabule pije a odkraglujem otisky nebot. Ex povidani pusta duse eh zvalel, o pak ma bryle luzka: u posluhovi neudela 30 ze ctverce brovninku. 411 se vi rypaje nova to per ba zchoulostivil remenem. Vaze to lujzou styky, te? Ne me by pazeni tro" "ubil i srovnala dejoveho a prvnich me o zime hlasy nevsimnou. Jejim zajiste za porotam valka sekt. Oni vuli co ryb pruvod. Ode jehoz od lasce ve slouzilo co jektal hryzal lamparny. Zvlastnich ne vybil brejlil uz ah? Husa trit mu straze s zivaje abys chute" " pane ci nepochybujte ubiha k babe ach okoli zle okna deji dverim! Vymyslim do falesne. Pokaceneho leti oka krk. Nohy stejny u vykaslu, rinkotem ondyno, laureat z zabije."
test.knot-resolver.cz. 3600 IN RRSIG TXT 13 3 3600 20370119135450 20190205122450 58 test.knot-resolver.cz. YYzbiOgNyIe2YcUHUbA8LNrqUYPSHEUA U7tAOLJx54kSlTMYDB5VrnqsAIgp2PtV C1gELBVK4Xtwxrx3ajeLhA==
;AUTHORITY
;ADDITIONAL
""")


@pytest.mark.parametrize("server", AUTHORITATIVE_SERVERS)
def test_udp_fragmentation(server):
    return answer_checker.send_and_check(LONG_QUERY,
                                         LONG_ANSWER,
                                         server,
                                         ALL)


QUERY_WITH_SMALL_PAYLOAD = answer_checker.make_query("test.knot-resolver.cz", "TXT", use_edns=0, payload=1280, want_dnssec=True)
TRUNCATED_ANSWER = dns.message.from_text("""id 17570
opcode QUERY
rcode NOERROR
flags QR AA RD TC
edns 0
payload 4096
;QUESTION
test.knot-resolver.cz. IN TXT
;ANSWER
;AUTHORITY
;ADDITIONAL
""")


@pytest.mark.parametrize("server", AUTHORITATIVE_SERVERS)
def test_udp_fragmentation_truncated(server):
    return answer_checker.send_and_check(QUERY_WITH_SMALL_PAYLOAD,
                                         TRUNCATED_ANSWER,
                                         server,
                                         ALL)
