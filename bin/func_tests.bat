@echo off

echo "Running functional tests..."
pytest src\tests\functional\test_main.py --token %CBC_AUTH_TOKEN%
