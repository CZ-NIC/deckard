#!/usr/bin/env python3
import os
from sg_scenario_full import *

def create_dir(dir):
    if not os.path.exists(dir):
        try:
            os.makedirs(dir)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

def response_difference(file, dir):
    sc = process_file(file)
    sc.check_answer_difference()

    f = ET.Element("File")
    f.set("file", file)
    for alter in sc.servers:
        if not alter.content_diff:
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

    create_dir(dir)
    output = dir + '/' if dir[-1] != '/' else ''
    output += file[:file.rfind(".")] + ".out"
    file = open(output, "w")
    file.write(string)
    file.close()
    print("Result successfully written into " + output)


# TODO: param - help, arguments
def main(argv):
    if len(argv) != 3:
        sys.stderr.write("Error: Invalid argument count\n")
        sys.exit(1)
    try:
	# Source file, output dir
    	diff = response_difference(sys.argv[1], sys.argv[2])
    except Exception as e:
        print("Error: ", end = '')
        print(e)
        exit(1)
    exit(0)

if __name__ == "__main__":
    main(sys.argv)
