@echo off

echo "Running tests..."
coverage run -m pytest --ignore=src\tests\functional

echo "Running report and sending to coveralls...."
coverage report -m
coveralls
