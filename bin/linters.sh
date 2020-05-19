#!/bin/sh

set -e

echo 'Running flake8....'
flake8 --docstring-convention google src/cbc_binary_toolkit/
flake8 --docstring-convention google src/tests/
