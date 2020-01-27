# -*- coding: utf-8 -*-

"""
Functions to read input received from file or command line, and output formatted JSON for the UBS to retrieve binaries
"""

import csv
import json
import logging
from math import ceil
from typing import List, Dict


def read_csv(filename: str) -> List[Dict]:
    """
    Function to read in a csv and return a JSON object of hashes

    Args:
        filename (str): The filename given as input to the function.
    Raises:
        AssertionError: incorrect length of a hash, or empty file
        OSError: File could not be found or read.
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS
    """

    json_dict_list: (List[Dict]) = []
    hash_list: (List[str]) = []

    try:
        with open(filename) as csvfile:
            file_data = csv.reader(csvfile)
            for row in file_data:
                hash = row[0]
                if len(hash) != 64:
                    raise AssertionError(f'Hash should be 64 chars, instead is {len(hash)} chars: {hash}')
                if hash not in hash_list:
                    hash_list.append(hash)
        if not hash_list:
            raise AssertionError(f'There are no hashes in File {filename}')

        json_dict_list = build_json_dicts_from_list(hash_list)
        return json_dict_list

    except (AssertionError, OSError) as err:
        logging.exception(err)
        raise


def read_json(json_string: str) -> List[Dict]:  # Assuming input = '{ "hashes": ["one","two"] }'
    """
    Function to read in a JSON string and return a JSON object of hashes

    Args:
        json_string (str): The JSON string received from the command line, to be parsed
    Raises:
        AssertionError: the input hashes array is empty.
        ValueError: malformed data in file.
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS
    """
    # limit of 100 hashes per call to UBS -- must return a list of dictionaries of up to 100 hashes each

    json_dict_list: (List[Dict]) = []
    try:
        json_dict = json.loads(json_string)

        if 'hashes' not in json_dict:
            raise KeyError("There is no hashes array in JSON object received from command line")

        all_hashes = json_dict['hashes']
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
        logging.exception(err)
        raise
    except json.decoder.JSONDecodeError as err:
        logging.exception(f'Malformed JSON input received: {err} for input {json_string}')
        raise


def build_json_dicts_from_list(hash_list: List[str]) -> List[Dict]:
    """
    Function to read in a list of strings and return a JSON object of hashes formatted for UBS

    Args:
        hash_list (List[str]): The JSON string received from the command line, to be parsed and split if > 100 hashes
    Returns:
        List of dictionaries containing up to 100 hashes each, formatted for UBS
    """
    json_dict_list: (List[Dict]) = []
    num_hashes = len(hash_list)

    if num_hashes > 100:  # UBS has a limit of 100 hashes per POST request to <psc-hostname>/ubs/<versionId>/orgs/<org_key>/file/_download
        num_dicts_req = ceil(num_hashes / 100)

        logging.info(f'The hashes array contains {num_hashes} hashes. Creating {num_dicts_req} JSON objects to send to UBS')

        for i in range(num_dicts_req):
            begin_index = i * 100
            if i == num_dicts_req - 1:  # building last dictionary
                end_index = begin_index + (num_hashes % 100)  # end at the last element in hash_list
            else:
                end_index = begin_index + 100

            json_dict_list.append({"hashes": hash_list[begin_index:end_index], "expiration_seconds": 3600})

    else:
        smaller_hash_dict = {"hashes": hash_list, "expiration_seconds": 3600}
        json_dict_list.append(smaller_hash_dict)

    return json_dict_list
