# BitterYear
Quickly parse DNSRECON output to save to note file in markdown table format and also add entries to /etc/hosts file.

# Usage

usage: BitterYear-runner.py [-h] [--file JSON_FILE] [--markdown MARKDOWN]

optional arguments:
  -h, --help           show this help message and exit
  --file JSON_FILE     File to parse.
  --markdown MARKDOWN  Markdown File to append data.

The input file to parse is a json output file from dnsrecon.  https://github.com/darkoperator/dnsrecon. 

# Extras

If you specify a markdown file to output to then the script will automatically replace a tag, [[ dnsrecon ]] with a markdown table.  Also if you have hostess (https://github.com/cbednarski/hostess) this script will add the server name to your /etc/hosts. 
