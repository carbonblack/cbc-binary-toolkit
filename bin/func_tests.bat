@echo off

echo "Running functional tests..."
pytest src\tests\functional\test_main.py --useshell TRUE --token %CBC_AUTH_TOKEN%
