#! /bin/bash

set -e

echo 'Running tests....'
coverage run -m pytest --ignore=functional

echo 'Running report and sending to coveralls....'
coverage report -m
coveralls
