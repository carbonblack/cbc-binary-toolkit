# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""
Functions to read input received from file or command line.

Output:
    Formatted JSON for the UBS to retrieve binaries
"""

import csv
import json
import logging

log = logging.getLogger(__name__)


def read_csv(file):
    """
    Function to read in a CSV file and return a list object of hashes

    Args:
        file (TextIOWrapper): The file given as input to the function

    Raises:
        AssertionError: incorrect length of a hash, or empty file
        OSError: File could not be found or read

    Returns:
        hashes (List): Extracted list of hashes.

    """
    hashes = list()

    try:
        with file as csvfile:
            file_data = csv.reader(csvfile)
            for row in file_data:
                if len(row) > 0:
                    hash_val = row[0]
                    if len(hash_val) != 64:
                        raise AssertionError(f'Hash should be 64 chars, instead is {len(hash_val)} chars: {hash_val}')
                    hashes.append(str(hash_val))
        if not hashes:
            raise AssertionError(f'There are no hashes in File {file.name}')

        return hashes

    except (AssertionError, OSError) as err:
        log.exception(err)
        raise


def read_json(json_string):
    """
    Function to read in a JSON string and return a JSON object of hashes

    Args:
        json_string (str): The JSON string received from the command line, to be parsed. Expected format: [str,]

    Raises:
        AssertionError: the input hashes array is empty, or there is an incorrect sha256 hash length
        KeyError: no "sha256" key in JSON input
        ValueError: malformed data in file

    Returns:
        List of hashes

    """
    try:
        json_input = json.loads(json_string)

        num_hashes = len(json_input)

        if num_hashes == 0:
            raise AssertionError('Hashes array contains no hashes')

        else:
            for hash in json_input:
                if len(hash) != 64:
                    raise AssertionError(f'Found hash with {len(hash)} chars instead of 64 chars for hash: {hash}')

        return json_input
    except AssertionError as err:
        log.exception(err)
        raise
    except json.decoder.JSONDecodeError as err:
        log.exception(f'Malformed JSON input received: {err} for input {json_string}')
        raise
