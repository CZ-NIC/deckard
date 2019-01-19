import ipaddress

import dns.message

import answer_checker

AUTHORITATIVE_SERVER = ipaddress.IPv4Address("127.0.0.1")
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

def test_zone_version():
    return answer_checker.send_and_check(VERSION_QUERY,
                                         VERSION_ANSWER,
                                         AUTHORITATIVE_SERVER,
                                         ALL)


QUERY = dns.message.make_query("test.knot-resolver.cz", "A", want_dnssec=True, payload=4096)
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
test.knot-resolver.cz.	3600	IN	RRSIG	A 13 3 3600 20370101093230 20190118080230 58 test.knot-resolver.cz. TEGT+vENDSfJ+dnu5sgUMF/BLCawEXW2G/bwhqtFla21Xie0985B+UU2 2unpmUdsQuZy92LeWCyANeFs0glEKA==
;AUTHORITY
;ADDITIONAL
""")

def test_remote_udp_53():
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         AUTHORITATIVE_SERVER,
                                         ALL)


def test_remote_tcp_53():
    return answer_checker.send_and_check(QUERY,
                                         ANSWER,
                                         AUTHORITATIVE_SERVER,
                                         ALL,
                                         tcp=True)


LONG_QUERY = dns.message.make_query("test.knot-resolver.cz", "TXT", use_edns=0, payload=4096, want_dnssec=True)
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
test.knot-resolver.cz.	3600	IN	RRSIG	TXT 13 3 3600 20370101093230 20190118080230 58 test.knot-resolver.cz. xZtk0SqCX/68Ezf94EUvsHjRw27QhzubKcgbgE5W873jZo2FaQNWOtUD K9wEqqih3osxiVR1qgyUXW7ouBfVDw==
;AUTHORITY
;ADDITIONAL
""")

def test_udp_fragmentation():
    return answer_checker.send_and_check(LONG_QUERY,
                                         LONG_ANSWER,
                                         AUTHORITATIVE_SERVER,
                                         ALL)

QUERY_WITH_SMALL_PAYLOAD = dns.message.make_query("test.knot-resolver.cz", "TXT", use_edns=0, payload=1280, want_dnssec=True)
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

def test_udp_fragmentation_truncated():
    return answer_checker.send_and_check(QUERY_WITH_SMALL_PAYLOAD,
                                         TRUNCATED_ANSWER,
                                         AUTHORITATIVE_SERVER,
                                         ALL)
