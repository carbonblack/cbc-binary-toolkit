# -*- coding: utf-8 -*-

"""
Functions to read input received from file or command line.

Output:
    Formatted JSON for the UBS to retrieve binaries
"""

import csv
import json
import logging
from math import ceil
from typing import List, Dict
from io import TextIOWrapper

log = logging.getLogger(__name__)


def read_csv(file: TextIOWrapper) -> List[Dict]:
    """
    Function to read in a csv and return a JSON object of hashes

    Args:
        file (TextIOWrapper): The file given as input to the function
    Raises:
        AssertionError: incorrect length of a hash, or empty file
        OSError: File could not be found or read
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS

    """
    json_dict_list: (List[Dict]) = []
    hash_dict: (Dict) = {}

    try:
        with file as csvfile:
            file_data = csv.reader(csvfile)
            for row in file_data:
                hash = row[0]
                if len(hash) != 64:
                    raise AssertionError(f'Hash should be 64 chars, instead is {len(hash)} chars: {hash}')
                if hash not in hash_dict:
                    hash_dict[hash] = 1
        if not hash_dict:
            raise AssertionError(f'There are no hashes in File {file.name}')

        hash_list = [key for key, val in hash_dict.items()]
        json_dict_list = build_json_dicts_from_list(hash_list)
        return json_dict_list

    except (AssertionError, OSError) as err:
        log.exception(err)
        raise


def read_json(json_string: str) -> List[Dict]:  # Assuming input = '{ "sha256": ["one","two"] }'
    """
    Function to read in a JSON string and return a JSON object of hashes

    Args:
        json_string (str): The JSON string received from the command line, to be parsed
    Raises:
        AssertionError: the input hashes array is empty, or there is an incorrect sha256 hash length
        KeyError: no "sha256" key in JSON input
        ValueError: malformed data in file
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS

    """
    # limit of 100 hashes per call to UBS -- must return a list of dictionaries of up to 100 hashes each

    json_dict_list: (List[Dict]) = []
    try:
        json_dict = json.loads(json_string)

        if 'sha256' not in json_dict:
            raise KeyError("There is no sha256 array in JSON object received from command line")

        all_hashes = json_dict['sha256']
        num_hashes = len(all_hashes)

        if num_hashes == 0:
            raise AssertionError('Hashes array contains no hashes')

        else:
            for hash in all_hashes:
                if len(hash) != 64:
                    raise AssertionError(f'Found hash with {len(hash)} chars instead of 64 chars for hash: {hash}')

            json_dict_list = build_json_dicts_from_list(all_hashes)

        return json_dict_list

    except (AssertionError, KeyError) as err:
        log.exception(err)
        raise
    except json.decoder.JSONDecodeError as err:
        log.exception(f'Malformed JSON input received: {err} for input {json_string}')
        raise


def build_json_dicts_from_list(hash_list: List[str]) -> List[Dict]:
    """
    Function to read in a list of strings and return a JSON object of hashes formatted for UBS
    UBS has a limit of 100 hashes per POST request to <psc-hostname>/ubs/<versionId>/orgs/<org_key>/file/_download

    Args:
        hash_list (List[str]): The JSON string received from the command line, to be parsed and split if > 100 hashes
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS

    """
    json_dict_list: (List[Dict]) = []
    num_hashes = len(hash_list)

    if num_hashes > 100:
        num_dicts_req = ceil(num_hashes / 100)

        log.info(f"The hashes array contains {num_hashes} hashes."
                 f" Creating {num_dicts_req} JSON objects to send to UBS")

        for i in range(num_dicts_req):
            begin_index = i * 100
            if i == num_dicts_req - 1:  # building last dictionary
                end_index = begin_index + (num_hashes % 100)  # end at the last element in hash_list
            else:
                end_index = begin_index + 100

            json_dict_list.append({"sha256": hash_list[begin_index:end_index], "expiration_seconds": 3600})

    else:
        smaller_hash_dict = {"sha256": hash_list, "expiration_seconds": 3600}
        json_dict_list.append(smaller_hash_dict)

    return json_dict_list
