# -*- coding: utf-8 -*-

"""BitterYear.BitterYear: provides entry point main()."""

__version__ = "0.1.0dev"

import argparse
import re
import sys
from glob import iglob
from json import loads
from json.decoder import JSONDecodeError
from os import curdir
from pathlib import Path
from shutil import which
from subprocess import run
from typing import Tuple

from inquirer import Confirm, prompt
from markdown_table import Table
from tabulate import tabulate


def confirm() -> bool:
    questions = [
        Confirm("continue", message="Would you like to add records to /etc/hosts")
    ]
    answer = prompt(questions)

    return answer["continue"]


def msg(message: str) -> str:
    return "[+] {0}".format(message)


def err_msg(message: str) -> str:
    return "[!] {0}".format(message)


def parse_a_records(json_obj) -> list:
    records = list()

    for obj in json_obj:
        # if the three keys are in then it contains A record info
        if all(x in obj.keys() for x in ["address", "type", "name"]):
            records.append(obj)

    return records


def render_md_table(columns: list, full_table: list) -> str:
    return Table(columns, full_table).render()


def render_text_info(data: list) -> str:
    output_string = ""
    output_string += "\nA Records\n"

    for item in data:

        output_string += "\tAddress : {0}\n".format(item["address"])
        output_string += "\tName: {0}\n\n".format(item["name"])

    return output_string


def render_tab_table(columns: list, full_table: list) -> str:
    return tabulate(full_table, headers=columns, tablefmt="fancy_grid")


def dnsinfo_to_table(records: list) -> Tuple[list, list]:

    columns = ["Address", "name"]
    full_table = []

    for record in records:
        # create table
        full_table.append([record["address"], record["name"]])

    return columns, full_table


def insert_md_table(markdown: str, md_table: str) -> None:
    content = open(markdown, "r").read(-1)

    # regex
    regex = r"\[\[\s?dnsrecon\s?\]\]"

    # if there exists a tag then substitute our data into it
    if re.findall(regex, content):
        re.sub(regex, md_table, content)
    else:
        content += md_table

    with open(markdown, "w") as m_file:
        m_file.write(content)


def add_json_file(json_files: list, json_file: str) -> None:

    try:
        json_files.append(loads(open(json_file, "r").read(-1)))
    except FileNotFoundError:
        print(err_msg("File path is not valid"))
    except JSONDecodeError:
        print(err_msg("File {0} was not valid json".format(json_file)))


def has_host_entry(hostess_bin: str, name: str) -> bool:
    cmd = [hostess_bin, "has", name]
    out = run(cmd, capture_output=True)

    if out.returncode == 0:
        return True

    return False


def add_host(hostess_bin: str, record: dict) -> None:
    cmd = [hostess_bin, "add", record["name"], record["address"]]
    run(cmd)


def main():
    print("Executing BitterYear version %s." % __version__)

    parser = argparse.ArgumentParser()
    parser.add_argument("--file", dest="json_file", help="File to parse.")
    parser.add_argument("--markdown", help="Markdown File to append data.")
    args = parser.parse_args()

    # holds all files to be processed
    json_files = list()

    # if a json file is provided then parse it
    if args.json_file:
        print(msg("Parsing json file {0}".format(args.json_file)))
        add_json_file(json_files, args.json_file)
    else:
        search_path = str(Path(curdir).joinpath("**/scans/dnsrecon/*"))
        dns_files = [f for f in iglob(search_path, recursive=True)]
        [add_json_file(json_files, dns_file) for dns_file in dns_files]

    a_records = list()
    [a_records.extend(parse_a_records(f)) for f in json_files]

    # get normal text output
    text_output = render_text_info(a_records)

    # create column and output data
    columns, table = dnsinfo_to_table(a_records)

    # if Output file given then write output to it
    if args.markdown:
        print(msg("Writing markdown to file"))
        md_table = render_md_table(columns, table)
        insert_md_table(args.markdown, md_table)

    print(msg("DNSRECON Results"))
    tabulate_table = render_tab_table(columns, table)

    print(tabulate_table)

    hostess_bin = which("hostess")
    print(msg("Located hostess binary at {0}".format(hostess_bin)))

    new_records = [
        record
        for record in a_records
        if not has_host_entry(hostess_bin, record["name"])
    ]

    if new_records:
        answer = confirm()
        [add_host(hostess_bin, record) for record in a_records]
    else:
        print(msg("All records already added to hosts"))
