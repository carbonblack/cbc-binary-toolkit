@echo off

echo "Running functional tests..."
coverage run -m pytest src\tests\functional\test_main.py --token %CBC_AUTH_TOKEN%
