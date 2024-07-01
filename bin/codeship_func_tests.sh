#! /bin/bash
# *******************************************************
# Copyright (c) Broadcom, Inc. 2020-2024. All Rights Reserved. Carbon Black.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

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
