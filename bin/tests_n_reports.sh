#! /bin/bash
set -e
coverage run -m pytest
coverage report -m
coveralls
