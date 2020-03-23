from glob import iglob
from json import loads
from json.decoder import JSONDecodeError
from os import curdir
from pathlib import Path
from shutil import which
from subprocess import run


class Util:
    def msg(self, message: str) -> str:
        if message is None:
            return "[+] NONE"

        return "[+] {0}".format(message)

    def err_msg(self, message: str) -> str:
        if message is None:
            return "[+] NONE"

        return "[!] {0}".format(message)

    def append_scan_log(self, app_name: str) -> None:

        if app_name is None:
            raise ValueError("Nonetype is not a valid application name")

        search_path = str(Path(curdir).joinpath("**/scans/*scan_overview*.md"))
        overview_path = [f for f in iglob(search_path, recursive=True)]

        if not overview_path:
            print(self.msg("Did not locate scanning overview"))
            return

        log_string = "* {0} Scan executed\n".format(app_name)
        with open(overview_path[0], "a+") as log:
            log.write(log_string)

    def create_scan_directory(self, path: str) -> str:

        p = Path(curdir).resolve().joinpath(path)
        p.mkdir(exist_ok=True, parents=True)
        return str(p)

    def add_json_file(self, json_files: list, json_file: str) -> None:
        """ Adds a json file to a list structure. Performing sanity
        checks as well as converting the text to json objects

            Arguments:
                json_files(list): Mutable list to add json objects to
                json_file(str): Path to json file to read

        """
        if not hasattr(json_files, "append"):
            raise ValueError("Parameter does not appear to be a list")

        if json_file is None:
            raise ValueError("file parameter appears to be of NoneType")

        try:
            json_files.append(loads(open(json_file, "r").read(-1)))
        except FileNotFoundError:
            print(Util().err_msg("File not found {0}".format(json_file)))
        except JSONDecodeError:
            print(Util().err_msg("File {0} was not valid json".format(json_file)))

    def ip_to_domains(self, ip: str) -> list:

        if ip is None:
            raise ValueError("Ip value is of NoneType")

        hostess_bin = which("hostess")
        if not hostess_bin:
            return []

        cmd = [hostess_bin, "dump"]
        out = run(cmd, capture_output=True)
        json = loads(out.stdout.decode("utf-8"))

        return [i["domain"] for i in json if i["ip"] == ip]
