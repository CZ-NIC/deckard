#!/usr/bin/env python3
import os
import argparse
import progressbar
import signal
import sys
from sg_scenario_full import *

stats = {}
count = 0
interrupted = False

def create_dir(dir):
    if not os.path.exists(dir):
        try:
            os.makedirs(dir)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

def response_difference(source):
    sc = process_file(source)
    sc.check_answer_difference()

    f = ET.Element("File")
    f.set("file", source)
    for alter in sc.servers:
        if not alter.content_diff:
            print("no diff")
            continue
        a = ET.SubElement(f, "Alternatives")
        s = ET.SubElement(a, "Servers")
        for ip in alter.names:
            i = ET.SubElement(s, "Server")
            i.set("IP", ip)
            i.set("name",alter.names[ip])
        qq = ET.SubElement(a, "Queries")
        for query in alter.content_diff:
            q = ET.SubElement(qq, "Query")
            q.set("name", query)
            content = alter.content_diff[query].split()
            for i in range(0, len(content), 2):
                q.set(content[i], content[i + 1])
    string = ET.tostring(f)
    string = parseString(string).toprettyxml()

    return string

def response_difference_stats(source):
    global stats
    sc = process_file(source)
    sc.check_answer_difference()

    for alter in sc.servers:
        for query in alter.content_diff:
            content = alter.content_diff[query].split()
            if "count" not in stats:
                stats["count"] = 1
            else:
                stats["count"] += 1
            for i in range(0, len(content), 2):
                if int(content[i+1]) > 1:
                    if content[i] not in stats:
                        stats[content[i]] = 1
                    else:
                        stats[content[i]] += 1

def save_output(string, output):
    if output != "stdout":
        file = open(output, "w")
        file.write(string)
        file.close()
        print("Result successfully written into " + output)
    else:
        print('\nResult:\n' + string)

def nsdiff_file(source, output):
    save_output(response_difference(source), output)

def nsdiff_dir(source, output):
    global count
    count = 0
    bar = progressbar.ProgressBar()
    for pcap_path in bar(os.listdir(source)):
        if interrupted:
            break
        pcap = os.fsdecode(pcap_path)
        response_difference_stats(os.path.join(source, pcap))
        count += 1
    save_output(str(stats), output)

def process_argv(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="File or directory with packets")
    parser.add_argument("output", help="File for program output (or stdout)")
    args = parser.parse_args()

    if os.path.isdir(args.source):
        nsdiff_dir(args.source, args.output)
    elif  os.path.isfile(args.source):
        nsdiff_file(args.source, args.output)
    else:
        print("Invalid source")
        exit(1)


def main(argv):
    process_argv(argv)

def interupt(signal, frame):
    global interrupted
    interrupted = True


if __name__ == "__main__":
    signal.signal(signal.SIGINT, interupt)
    signal.signal(signal.SIGTERM, interupt)
    main(sys.argv)
