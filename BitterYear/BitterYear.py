# -*- coding: utf-8 -*-

"""BitterYear.BitterYear: provides entry point main()."""

__version__ = "0.5"

import argparse
import re
import sys
from glob import iglob
from ipaddress import ip_address
from json import dumps, loads
from json.decoder import JSONDecodeError
from os import curdir, environ
from pathlib import Path
from shutil import which
from subprocess import CompletedProcess, run
from threading import Thread
from typing import Tuple

from inquirer import Checkbox, Confirm, List, Text, prompt
from markdown_table import Table
from tabulate import tabulate

from BitterYear.markdown import Markdown
from BitterYear.Util import Util


def run_binary(
    dnsrecon_bin: str, domain_name: str, options: dict, cmd_output: list
) -> None:
    """ Runs the dnsrecon command with given options.

        Arguments:
            dnsrecon_bin(str): Path string to dnsrecon
            options(dict): dictionary containing options needed for running
            domain_name(str): Target domain name
            cmd_output(list): List to append command output to

    """
    # create report name
    json_report = str(
        Path(options["output_path"]).joinpath("{0}.json".format(domain_name))
    )
    csv_report = str(
        Path(options["output_path"]).joinpath("{0}.csv".format(domain_name))
    )
    sqlite = str(Path(options["output_path"]).joinpath("{0}.db".format(domain_name)))

    cmd = list()
    cmd.extend([dnsrecon_bin])
    cmd.extend(["-d", domain_name])
    cmd.extend(["-a"])
    cmd.extend(["-n", options["name_server"]])
    cmd.extend(["-j", json_report])
    cmd.extend(["-c", csv_report])
    cmd.extend(["--db", sqlite])

    print("Starting : {0} ".format(domain_name))
    output = run(cmd, capture_output=True)
    print("Finished : {0}".format(domain_name))

    cmd_output.append(
        {"results": output, "cmd": " ".join(cmd), "json_report": json_report}
    )


def validate_input(args) -> ip_address:
    """ Validates and formulates user input. This function can make default
    decisions about where to get environment variable input from and what form
    it should take.

        Arguments:
            args(argparser): Arguments to validate

        Return:
            ip_address: Default target ip address

    """
    # determine if the input IP address is inface an IP
    ip = None

    try:
        # if no target host given
        if not args.target:
            # look for RHOST environ var
            if "RHOST" in environ.keys():
                print(Util().msg("Using Environment variable for IP address"))
                ip = ip_address(environ["RHOST"])
        else:
            ip = ip_address(args.target)

    except ValueError:
        print(
            Util().err_msg(
                "Argument or environment variable was not a valid IP address"
            )
        )
        sys.exit()

    return ip


def info_to_table(rows: list) -> Tuple[list, list]:
    """ Formats raw row data into a table format that will be used
    with other render functions. This function is where column headers
    should be defined.

        Arguments:
            rows(list): Rows of data

        Return:
            List : List of column names
            List : Full table representation of data
    """
    columns = ["Address", "Name", "Type"]
    full_table = []

    for row in rows:
        # create table
        full_table.append([row["address"], row["name"], row["type"]])

    return columns, full_table


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


def generate_options(rhost: str) -> dict:
    """
        dnsrecon -d {HOSTNAME} -n {Nameserver IP} -j {json file}
    """

    questions = list()

    pre_questions = [
        Confirm(
            "use_ip", default=True, message="Use IP {0} for Name Server".format(rhost)
        ),
    ]

    pre_answers = prompt(pre_questions)

    # If we decided against using an IP
    if not pre_answers["use_ip"]:
        questions.append(Text("name_server", message="Input Name Server"))

    # Are there items that match etc host defs
    domains = Util().ip_to_domains(rhost)
    if domains:
        questions.append(
            Checkbox("domains", message="Input domain to search", choices=domains)
        )
    else:
        questions.append(Text("domains", message="Input domain to search"))

    answers = prompt(questions)

    # annotate answers
    if pre_answers["use_ip"]:
        answers["name_server"] = rhost

    # if we put in only one domain name then turn it into a list
    if not hasattr(answers["domains"], "sort"):
        answers["domains"] = [answers["domains"]]

    return answers


def has_host_entry(hostess_bin: str, name: str) -> bool:
    cmd = [hostess_bin, "has", name]
    out = run(cmd, capture_output=True)

    if out.returncode == 0:
        return True

    return False


def add_host_records(hostess_bin: str, new_records: list) -> None:

    if not new_records:
        return

    questions = [
        Confirm("continue", message="Would you like to add records to /etc/hosts")
    ]

    answer = prompt(questions)["continue"]

    if answer:
        for record in new_records:
            cmd = [hostess_bin, "add", record["name"], record["address"]]
            run(cmd)


def perform_scan(args):

    dnsrecon_bin = which("dnsrecon")
    if not dnsrecon_bin:
        print(Util().err_msg("Unable to locate dnsrecon binary"))
        return

    print(Util().msg("Located dnsrecon binary : {0}".format(dnsrecon_bin)))
    ip = validate_input(args)

    str_ip = str(ip) if ip else ""

    # Get options for run
    dnsrecon_options = generate_options(str_ip)
    dnsrecon_options["output_path"] = Util().create_scan_directory("scans/dnsrecon")

    outputs = list()

    threads = {
        domain_name: Thread(
            target=run_binary,
            args=(dnsrecon_bin, domain_name, dnsrecon_options, outputs),
        )
        for domain_name in dnsrecon_options["domains"]
    }

    [t.start() for t in threads.values()]
    [t.join() for t in threads.values()]

    if args.save_cmd:
        filename = str(Path(curdir).joinpath("cmd.sh"))
        with open(filename, "w") as cmd_sh:
            [cmd_sh.write("{0}\n".format(o["cmd"])) for o in outputs]

    # load json file from output
    json_objs = list()
    [
        Util().add_json_file(json_objs, output["json_report"])
        for output in outputs
        if "json_report" in output.keys()
    ]

    print(Util().msg("Parsing Output returned from dnsrecon"))
    all_a_records = [parse_records(json_obj, "A") for json_obj in json_objs]
    all_srv_records = [parse_records(json_obj, "SRV") for json_obj in json_objs]

    a_records = [row for record in all_a_records for row in record]
    srv_records = [row for record in all_srv_records for row in record]

    # create column and output data
    tables = info_to_table(a_records)
    srv_tables = info_to_table(srv_records)

    # if Output file given then write output to it
    if args.markdown:
        print(Util().msg("Writing markdown to file"))
        md_table = render_md_table(columns, table)
        Markdown().insert_md_table(args.markdown, md_table, "BLACKWAR")

    print(Util().msg("Results"))
    if a_records:
        print("All A Records")
        print(render_tab_table(tables[0], tables[1]))
    if srv_records:
        print("All SRV Records")
        print(render_tab_table(srv_tables[0], srv_tables[1]))


def process_scan():

    # holds all files to be processed
    json_files = list()

    search_path = str(Path(curdir).joinpath("**/scans/dnsrecon/*"))
    dns_files = [f for f in iglob(search_path, recursive=True)]
    [Util().add_json_file(json_files, dns_file) for dns_file in dns_files]

    a_records = list()
    [a_records.extend(parse_a_records(f)) for f in json_files]

    # get normal text output
    text_output = render_text_info(a_records)

    # create column and output data
    columns, table = dnsinfo_to_table(a_records)

    print(Util().msg("DNSRECON Results"))
    tabulate_table = render_tab_table(columns, table)

    print(tabulate_table)

    return a_records


def main():
    print("Executing BitterYear version %s." % __version__)

    parser = argparse.ArgumentParser(description="Parse dnsrecon records")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--target", default="None", help="IP address for Name Server.")
    group.add_argument(
        "--process-only",
        dest="proc_only",
        action="store_true",
        help="Process data only.",
    )
    parser.add_argument(
        "--save-cmd",
        dest="save_cmd",
        action="store_true",
        help="Save cmd output to file",
    )
    parser.add_argument("--markdown", help="Write data to markdown file")
    args = parser.parse_args()

    if args.proc_only:

        print(Util().msg("Processing json files"))
        a_records = process_scan()

    else:

        print(Util().msg("Performing dnsrecon"))
        a_records = perform_scan(args)

    if a_records:

        hostess_bin = which("hostess")
        print(Util().msg("Located hostess binary at {0}".format(hostess_bin)))

        new_records = [
            record
            for record in a_records
            if not has_host_entry(hostess_bin, record["name"])
        ]

        add_host_records(hostess_bin, new_records)

    else:
        print(Util().msg("No records found"))
