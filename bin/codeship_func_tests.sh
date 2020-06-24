#! /bin/bash

echo "Running functional tests..."
pytest src/tests/functional/test_main.py --token $CBC_AUTH_TOKEN

aws s3 cp /app/src/tests/functional/log.txt s3://binarytoolkit-functional-tests/$CI_TIMESTAMP.$1.log.txt
