#!/bin/sh

set -e

echo 'Running flake8....'
flake8 --docstring-convention google cb_binary_analysis/*.py
flake8 --docstring-convention google tests/*.py
