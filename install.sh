#!/bin/bash
pip3 uninstall BitterYear
python3 setup.py develop
pip3 install -e . --force-reinstall
