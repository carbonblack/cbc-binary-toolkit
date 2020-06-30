#! /bin/bash

set -e

echo 'Running tests....'
coverage run -m pytest --ignore=src/tests/functional --ignore=src/tests/load

echo 'Running report and sending to coveralls....'
coverage report -m
coveralls
