#!/usr/bin/env python3
from sg_scenario_full import *
import argparse
import os

#Generate scenario and save the result.
def print_scenario(args):
    sc = process_file(args.source)
    if args.name:
        sc.add_name(args.description)
    else:
        sc.add_name(args.source)
    # Return scenario
    if args.output != "stdout":
        file = open(args.output, "w")
        file.write(sc.to_string())
        file.close()
        print("Result successfully written into " + args.output)
    else:
        print('Result:\n' + sc.to_string())

#Process command line arguments
def process_argv(argv):
    parser = argparse.ArgumentParser(prog='SGEN')
    parser.add_argument("source", help="PCAP file")
    parser.add_argument("output", nargs='?', default="stdout", help="Output file (stdout as default)")
    parser.add_argument("-d", "--description", help="Scenario description")
    parser.add_argument("-o", "--one", action='store_true', help="Use only one nameserver per zone")
    parser.add_argument("-6", "--ipv6", action='store_true', help="Disable IPv6")
    args = parser.parse_args()

    print(args)
    if os.path.isfile(args.source):
        return args
    else:
        print("Invalid source")
        exit(1)

# TODO: content to class?
# TODO: multiple names per server
# TODO: test on smaller pcaps - takes too long to resolve everything
# TODO: ON/OFF ipv6 - implement
# TODO: file as output - implement
# TODO: one ns per zone - implement
# TODO: Check and reuse the actual queries - now root servers dont fit 
def main(argv):
    args = process_argv(argv)
    print_scenario(args)
    exit(0)

if __name__ == "__main__":
    main(sys.argv)
