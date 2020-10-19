"""
Generate new keys with the same attributes as the keys in json file

usage: keygen.py [-h] [-d KEY_DIR] [-o OUTPUT] [-b BLACKLIST [BLACKLIST ...]]
                 key_map

positional arguments:
  key_map               path to file with the keymap

optional arguments:
  -h, --help            show this help message and exit
  -d KEY_DIR, --key_dir KEY_DIR
                        path to the directory where the keys will be stored,
                        default is working directory
  -o OUTPUT, --output OUTPUT
                        path to the output file, default is replaced_keys.json
                        in working directory
  -b BLACKLIST [BLACKLIST ...], --blacklist BLACKLIST [BLACKLIST ...]
                        key tags which cannot be used
"""


import argparse
import json
import os
import shutil
import subprocess
import sys
import logging


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_dependency():
    """
    Ends script if dnssec-keygen is not installed
    """
    if shutil.which("dnssec-keygen") is None:
        logger.error("Missing program dnssec-keygen.")
        sys.exit(1)


def parseargs():
    """
    Parse arguments of the script

    Return:
        key_map (str)   path to file with the keymap
        blacklist (str) list of key tags which cannot be used
        key_dir (str)   path to the directory with the keys
        output (str)    path to the output file
    """
    argparser = argparse.ArgumentParser()
    argparser.add_argument("key_map",
                           help="path to file with the keymap")
    argparser.add_argument("-d", "--key_dir",
                           help="""path to the directory where the keys will be stored,
                           default is working directory""", default=".")
    argparser.add_argument("-o", "--output",
                           help="""path to the output file,
                           default is replaced_keys.json in working directory""",
                           default="replaced_keys.json")
    argparser.add_argument("-b", "--blacklist",
                           help="key tags which cannot be used", type=int, nargs='+',
                           default=[])
    args = argparser.parse_args()

    if not os.path.isfile(args.key_map):
        logger.error("%s is not a file.", args.key_map)
        sys.exit(1)
    if not os.path.exists(args.key_dir):
        os.makedirs(args.key_dir)
    return args.key_map, args.blacklist, args.key_dir, args.output


def readkeys(path):
    """
    Read information about keys from json file

    Attributes:
        path (str)      path to the json file

    Return:
        list of dictionaries with info about the keys
    """
    with open(path) as map_file:
        keys = json.load(map_file)
    return keys


def generate_key(key, blacklist, key_dir):
    """
    generate key with attributes given by key dictionaty

    Attributes:
        key (dict)              key dictionary with keys "flags", "algorithm" and "owner"
        blacklist (list of int) key tags which cannot be used
        key_dir                 directory where generated keys will be stored
    """
    command = ["dnssec-keygen"]
    if key["flags"] == 257:
        command += ["-f", "ksk"]
    command += ["-K", key_dir, "-b", "1024"]  # TODO: řešit velikost klíče?
    command += ["-a", str(key["algorithm"]), "-n", "ZONE", key["owner"]]
    keygen = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    keygen_output = keygen.communicate()
    if keygen.returncode != 0:
        logger.error("Cannot generate key:\n%s", keygen_output[1].decode("utf-8"))
        sys.exit(1)
    filename = keygen_output[0].decode("utf-8").split("\n")[-2]
    tag = int(filename.split("+")[-1])
    filename += ".key"
    if tag in blacklist:    # TODO: soubor tam nechat?
        return generate_key(key, blacklist, key_dir)
    blacklist.append(tag)
    return tag, filename


def main():
    """
    Generate new keys with the same attributes as the keys in json file
    """
    check_dependency()
    key_map, blacklist, key_dir, output = parseargs()
    keys = readkeys(key_map)
    changed_keys = []
    for key in keys:
        new_tag, filename = generate_key(key, blacklist, key_dir)
        changed = {}
        changed["old"] = key["tag"]
        changed["new"] = new_tag
        changed["file"] = filename
        changed_keys.append(changed)
    with open(output, "w") as output_file:
        json.dump(changed_keys, output_file, indent=4)


main()
