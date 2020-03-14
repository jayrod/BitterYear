# -*- coding: utf-8 -*-

"""BitterYear.BitterYear: provides entry point main()."""

__version__ = "0.1.0dev"

import sys
import argparse
from pathlib import Path
from json import loads
from json.decoder import JSONDecodeError

def msg(message: str) -> str:
    return "[+] {0}".format(message)

def err_msg(message: str) -> str:
    return "[!] {0}".format(message)


def parse_a_records(json_obj) -> list:
    records = list()

    for obj in json_obj:
        #if the three keys are in then it contains A record info
        if all(x in obj.keys() for x in ['address', 'type', 'name']):
            print(obj)
            
    return records

def main():
    print("Executing BitterYear version %s." % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", dest='json_file', help="File to parse.")
    args = parser.parse_args()

    #holds all files to be processed
    json_files = list()

    if args.json_file:
        print(msg("Parsing json file {0}".format(args.json_file)))
        try:
            json_files.append(loads(open(args.json_file, 'r').read(-1)))
        except FileNotFoundError:
            print(err_msg("File path is not valid"))
            sys.exit(1)
        except JSONDecodeError:
            print(err_msg("File was not valid json"))
            sys.exit(1)

         
    a_records = list()
    [a_records.extend(parse_a_records(f)) for f in json_files]
