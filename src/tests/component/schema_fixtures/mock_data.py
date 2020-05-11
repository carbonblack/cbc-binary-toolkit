# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2019. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Mock data for test code"""


VALID_IOCV2 = {
    "id": "43fgsf2g",
    "match_type": "query",
    "values": ["value"],
    "severity": 2
}

INVALID_SEVERITY_IOCV2 = {
    "id": "43fgsf2g",
    "match_type": "query",
    "values": ["value"],
    "severity": 20
}

INVALID_MATCH_TYPE_IOCV2 = {
    "id": "43fgsf2g",
    "match_type": "INVALID",
    "values": ["value"],
    "severity": 2
}

MISSING_VALUE_IOCV2 = {
    "id": "43fgsf2g",
    "match_type": "query",
    "values": [],
    "severity": 2
}

VALID_REPORT = {
    "id": "asdoui1qw8f9h",
    "timestamp": 1900099237,
    "title": "Engine Report",
    "description": "Automated",
    "severity": 2,
    "iocs_v2": [],
}

INVALID_SEVERITY_REPORT = {
    "id": "asdoui1qw8f9h",
    "timestamp": 1900099237,
    "title": "Engine Report",
    "description": "Automated",
    "severity": 0,
    "iocs_v2": [],
}

MISSING_PROPERTIES_REPORT = {
    "id": "asdoui1qw8f9h",
    "timestamp": 1900099237,
    "severity": 2,
    "iocs_v2": [],
}

VALID_ENGINE_RESPONSE = {
    "iocs": [],
    "engine_name": "Engine Example",
    "binary_hash": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "success": True
}

INVALID_SHA256_ENGINE_RESPONSE = {
    "iocs": [],
    "engine_name": "Engine Example",
    "binary_hash": "INVALID",
    "success": True
}

VALID_BINARY_METADATA = {
    "sha256": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "url": "http://aws.url",
    "architecture": ["amd64"],
    "available_file_size": 1024,
    "charset_id": 1,
    "comments": "",
    "company_name": "",
    "copyright": "",
    "file_available": True,
    "file_description": "",
    "file_size": 1024,
    "file_version": "",
    "internal_name": "",
    "lang_id": 4,
    "md5": "1278oakjsdlkahlvuyoi2387ehan112c",
    "original_filename": "",
    "os_type": "",
    "private_build": "",
    "product_description": "",
    "product_name": None,
    "product_version": None,
    "special_build": None,
    "trademark": None
}


INVALID_SHA256_BINARY_METADATA = {
    "sha256": "INVALID",
    "url": "http://aws.url",
    "architecture": ["amd64"],
    "available_file_size": 1024,
    "charset_id": 1,
    "comments": "",
    "company_name": "",
    "copyright": "",
    "file_available": True,
    "file_description": "",
    "file_size": 1024,
    "file_version": "",
    "internal_name": "",
    "lang_id": 4,
    "md5": "1278oakjsdlkahlvuyoi2387ehan112c",
    "original_filename": "",
    "os_type": "",
    "private_build": "",
    "product_description": "",
    "product_name": None,
    "product_version": None,
    "special_build": None,
    "trademark": None
}

MISSING_FIELDS_BINARY_METADATA = {
    "sha256": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "url": "http://aws.url",
    "architecture": ["amd64"],
    "available_file_size": 1024,
    "charset_id": 1,
    "comments": "",
    "company_name": "",
    "copyright": "",
    "file_available": True,
    "file_description": "",
    "file_size": 1024,
    "file_version": "",
    "internal_name": "",
    "lang_id": 4,
    "md5": "1278oakjsdlkahlvuyoi2387ehan112c",
    "original_filename": "",
    "os_type": ""
}

INVALID_MD5_BINARY_METADATA = {
    "sha256": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "url": "http://aws.url",
    "architecture": ["amd64"],
    "available_file_size": 1024,
    "charset_id": 1,
    "comments": "",
    "company_name": "",
    "copyright": "",
    "file_available": True,
    "file_description": "",
    "file_size": 1024,
    "file_version": "",
    "internal_name": "",
    "lang_id": 4,
    "md5": "INVALID",
    "original_filename": "",
    "os_type": "",
    "private_build": "",
    "product_description": "",
    "product_name": None,
    "product_version": None,
    "special_build": None,
    "trademark": None
}

EMPTY_URL_BINARY_METADATA = {
    "sha256": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
    "url": "",
    "architecture": ["amd64"],
    "available_file_size": 1024,
    "charset_id": 1,
    "comments": "",
    "company_name": "",
    "copyright": "",
    "file_available": True,
    "file_description": "",
    "file_size": 1024,
    "file_version": "",
    "internal_name": "",
    "lang_id": 4,
    "md5": "1278oakjsdlkahlvuyoi2387ehan112c",
    "original_filename": "",
    "os_type": "",
    "private_build": "",
    "product_description": "",
    "product_name": None,
    "product_version": None,
    "special_build": None,
    "trademark": None
}
