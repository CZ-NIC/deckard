#!/usr/bin/python

import argparse
import logging
import random
import sys

import dns.name
import dns.flags
import dns.message
import dns.resolver
import dns.query

import equivalence

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
    """collect answers from all servers"""
    q = dns.message.make_query(qname, qtype, want_dnssec=True, request_payload=4096, payload=4096)
    q.flags = 0  # no RD
    q.id = 0
    logging.debug('prepared query: %s', q)
    answers = set()
    for ip, nsname in servers.items():
        q.id = random.randint(0, 0xffff)  # use new ID for each query
        logging.info('querying %s (%s), id %s', ip, nsname, q.id)
        a = dns.query.udp(q, ip, timeout=5)
        logging.debug('answer from %s: %s', ip, a)
        a.hack_source_ip = ip
        answers.add(a)
    return answers

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    argparser = argparse.ArgumentParser()
    argparser.add_argument('qname', type=dns.name.from_text, help='query name')
    argparser.add_argument('qtype',
                           help='RR type (default: A)', nargs='?', default='A')
    # argparser.add_argument('+noadditional', type=bool, help='do not compare additional sections')
    args = argparser.parse_args()
    qname = args.qname
    try:
        qtype = int(args.qtype)
    except ValueError:
        qtype = dns.rdatatype.from_text(args.qtype)

    logging.debug('query %s %s', qname, dns.rdatatype.to_text(qtype))
    logging.debug('determining zone containing "%s"', qname)
    zname = dns.resolver.zone_for_name(qname)
    logging.info('name "%s" belongs to zone "%s"', qname, zname)
    servers = get_zone_servers(zname)
    answers = get_answers(qname, qtype, servers)

    equiv_classes = equivalence.partition_messages(answers)
    print('Received {0} distinct answers'.format(len(equiv_classes.keys())))
    for ips, a in equiv_classes.items():
        print('Answer from servers: {0}'.format(ips))
        print(a)

    #debug
    vals = equiv_classes.values()
    a0 = vals[0].additional
    a1 = vals[1].additional
    a2 = vals[2].additional

