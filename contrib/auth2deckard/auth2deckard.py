#!/usr/bin/python

import argparse
import logging
import random
import sys
import socket

import dns.name
import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.query

import equivalence
import pydnstest.scenario


# monkey-patch comparison functions:
# DNS message equality is based on message content, not metadata
dns.message.Message.__eq__ = equivalence.compare_dns_messages
dns.message.Message.__ne__ = lambda x, y: not equivalence.compare_dns_messages(x, y)

def get_ip_addresses(qname):
    addresses = set()
    for qtype in {'A', 'AAAA'}:
        try:
            answer = dns.resolver.query(qname, qtype)
            for rr in answer.rrset:
                addresses.add(rr.address)
        except dns.resolver.NoAnswer as ex:
            logging.debug('NS "%s" does not have "%s" record', qname, qtype)
    return addresses

def get_zone_servers(zname):
    """:returns: dict {'IP address': 'DNS server name'}"""
    servers = {}
    nsset = dns.resolver.query(zname, 'NS')
    for ns in nsset.rrset:
        nsname = ns.target.canonicalize()
        for addr in get_ip_addresses(nsname):
            servers[addr] = nsname
    logging.debug('NS for zone "%s": %s', zname, servers)
    return servers

def get_answers(qname, qtype, servers):
    """
    collect answers from all servers

    returns: dict {ip: <DNS message>}
    """
    q = dns.message.make_query(qname, qtype, want_dnssec=True, request_payload=4096, payload=4096)
    q.flags = 0  # no RD
    q.id = 0
    logging.debug('prepared query: %s', q)
    answers = {}
    for ip, nsname in servers.items():
        q.id = random.randint(0, 0xffff)  # use new ID for each query
        logging.info('querying %s (%s), id %s', ip, nsname, q.id)
        attempts = 5
        while attempts > 0:
            try:
                a = dns.query.udp(q, ip, timeout=5)
                logging.debug('answer from %s: %s', ip, a)
                attempts = 0
            except (socket.error, dns.exception.Timeout) as ex:
                attempts -= 1
                logging.exception(ex)
                # synthesise fake SERVFAIL because Deckard does not support timeouts yet
                a = dns.message.make_response(q)
                a.set_rcode(dns.rcode.SERVFAIL)
            finally:
                a.hack_source_ip = ip
        answers[ip] = a
    return answers


def get_authoritative_answers(qname, qtype, parent):
    """
    return authoritative answers to a given query

    returns: dict {IP address: <DNS message>}
    """
    logging.debug('query %s %s', qname, dns.rdatatype.to_text(qtype))
    logging.debug('determining zone containing "%s"', qname)
    zname = dns.resolver.zone_for_name(qname)
    logging.info('name "%s" belongs to zone "%s"', qname, zname)
    if parent and qname != dns.name.root:
        zparentname = dns.name.Name(zname[1:])
        logging.debug('looking up parent servers (for zone %s)', zparentname)
        servers = get_zone_servers(zparentname)
    else:
        servers = get_zone_servers(zname)
    return get_answers(qname, qtype, servers)


def merge_server_answers(*answer_dicts):
    """
    merge answer dicts into one

    input: dict {IP address: <DNS message>}
    returns: dict {IP address: dns.set.Set [<DNS messages>]}
    """
    merged = {}
    for answer_dict in answer_dicts:
        for ip, answer in answer_dict.items():
            answer_set = merged.setdefault(ip, dns.set.Set())
            answer_set.add(answer)
    return merged


def prepare_query_params(qname, qtype, parent=False):
    if not isinstance(qname, dns.name.Name):
        qname = dns.name.from_text(qname)
    parent = bool(parent)
    try:
        qtype = int(qtype)
    except ValueError:
        qtype = dns.rdatatype.from_text(qtype)
    if qtype == dns.rdatatype.DS:
        parent = True
    return (qname, qtype, parent)

def file_to_querylist(infile):
    qlist = []
    for line in infile:
        logging.debug('query line: %s', line)
        params = line.split()
        qlist.append(prepare_query_params(*params))
    return qlist


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    argparser = argparse.ArgumentParser()
    arg_one_query = argparser.add_argument_group('one query')
    arg_one_query.add_argument('qname', type=dns.name.from_text, help='query name', nargs='?')
    arg_one_query.add_argument('qtype',
                           help='RR type (default: A)', nargs='?', default='A')
    arg_one_query.add_argument('--parent', action='store_const', const=True,
                           help='query parent servers (whose delegate to zone in question)')

    arg_qlist = argparser.add_argument_group('query list from file')
    arg_qlist.add_argument('--qlist', type=open, help='query list file name (format: qname qtype [parent?])')

    # argparser.add_argument('+noadditional', type=bool, help='do not compare additional sections')
    args = argparser.parse_args()

    # subcommands are overkill for our simple case
    if args.qname:
        if args.qlist:
            sys.exit('qname and --qlist cannot be used together')
        qlist = [prepare_query_params(args.qname, args.qtype, args.parent)]
    elif args.qlist:
        qlist = file_to_querylist(args.qlist)
    else:
        sys.exit('Either qname or --qlist is required')

    # get answers to all queries
    answers = []
    for qname, qtype, parent in qlist:
        answers.append(get_authoritative_answers(qname, qtype, parent))
    merged = merge_server_answers(*answers)
    ec = equivalence.equivalence_named(merged.items(), lambda x, y: x == y)
    #for c, msgs in ec.items():
    #    pprint(c)
    #    for m in msgs:
    #        print(m)
    #sys.exit(0)

    logging.info('Answers form {0} distinct ranges'.format(len(ec)))
    for ips, answers in ec.items():
        r = pydnstest.scenario.Range(0, 10000)
        r.addresses = set(ips)
        for answer in answers:
            entry = pydnstest.scenario.Entry()
            entry.message = answer
            # this is fragile when it comes to non-compliant servers
            if not answer.flags & dns.flags.AA and answer.authority:
                logging.debug('non-authoritative answer with AUTHORITY section detected, adjusting MATCH and ADJUST fields')
                entry.match_fields = ['opcode', 'subdomain']
                entry.adjust_fields.append('copy_query')
            r.add(entry)
        print(r)

        #print('Answer from servers: {0}'.format(ips))
        #print(a)

