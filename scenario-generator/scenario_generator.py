#!/usr/bin/env python3
from sg_scenario_full import *

def print_scenario(file, name="No name"):
    sc = process_file(file)
    sc.add_name(name)
    # Return scenario
    print(sc.to_string())

# TODO: content to class?
# TODO: multiple names per server
# TODO: test on smaller pcaps - takes too long to resolve everything
# TODO: ON/OFF ipv6
# TODO: file as output
# TODO: Check and reuse the actual queries - now root servers dont fit 
def main(argv):
    if len(argv) != 3:
        sys.stderr.write("Invalid argument count\n")
        sys.exit(1)
    try:
        print_scenario(sys.argv[1], sys.argv[2])
    except Exception as e:
        print(e)
        exit(1)
    exit(0)


if __name__ == "__main__":
    main(sys.argv)
