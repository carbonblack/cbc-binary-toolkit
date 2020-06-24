#! /bin/bash

echo "Running functional tests..."
pytest src/tests/functional/test_main.py --token $CBC_AUTH_TOKEN

if [ $? -eq 0 ]
then
  exit 0
else
  echo "Pushing log file to S3..."
  aws s3 cp /app/src/tests/functional/log.txt s3://binarytoolkit-functional-tests/$CI_COMMIT_ID.$1.log.txt
  exit 1
fi
