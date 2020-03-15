# -*- coding: utf-8 -*-


"""setup.py: setuptools control."""


import re
from os.path import exists

from setuptools import setup

version = re.search(
    '^__version__\s*=\s*"(.*)"', open("BitterYear/BitterYear.py").read(), re.M
).group(1)

if exists("README.md"):
    with open("README.md", "rb") as f:
        long_descr = f.read().decode("utf-8")
else:
    long_descr = ("Quickly parse dnsrecon output for note taking.",)

setup(
    name="cmdline-BitterYear",
    packages=["BitterYear"],
    entry_points={"console_scripts": ["BitterYear = BitterYear.BitterYear:main"]},
    version=version,
    description="Quickly parse dnsrecon output for note taking.",
    install_requires=[
        "inquirer>=2.6.3",
        "markdown_table>=2019.4.13",
        "tabulate>=0.8.6",
    ],
    long_description=long_descr,
    author="",
    author_email="",
)
