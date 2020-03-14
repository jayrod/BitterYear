# -*- coding: utf-8 -*-


"""setup.py: setuptools control."""


import re
from os.path import exists
from setuptools import setup


version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('BitterYear/BitterYear.py').read(),
    re.M
    ).group(1)

if exists("README.md"):
    with open("README.md", "rb") as f:
        long_descr = f.read().decode("utf-8")
else:
    long_descr = "Quickly parse dnsrecon output for note taking.",

setup(
    name = "cmdline-BitterYear",
    packages = ["BitterYear"],
    entry_points = {
        "console_scripts": ['BitterYear = BitterYear.BitterYear:main']
        },
    version = version,
    description = "Quickly parse dnsrecon output for note taking.",
    long_description = long_descr,
    author = "",
    author_email = "",
    )
