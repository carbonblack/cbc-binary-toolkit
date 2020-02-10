#!/bin/sh
set -e
echo 'Running flake8....'
flake8 cb_binary_analysis/*.py
flake8 tests/*.py
