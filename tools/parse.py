"""Returns 0 if the test is parsed, 1 if not."""

import sys
import os
import argparse
# sys.path.insert(0, '..')
import pydnstest
import pydnstest.scenario


def main():
    """Returns 0 if the test is parsed, 1 if not."""
    argparser = argparse.ArgumentParser()
    argparser.add_argument("file")
    args = argparser.parse_args()
    if pydnstest.scenario.parse_file(os.path.realpath(args.file)):
        sys.exit(0)
    else:
        sys.exit(1)

main()
