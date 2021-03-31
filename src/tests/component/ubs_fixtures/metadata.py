# -*- coding: utf-8 -*-

# *******************************************************
# Copyright (c) VMware, Inc. 2020-2021. All Rights Reserved.
# SPDX-License-Identifier: MIT
# *******************************************************
# *
# * DISCLAIMER. THIS PROGRAM IS PROVIDED TO YOU "AS IS" WITHOUT
# * WARRANTIES OR CONDITIONS OF ANY KIND, WHETHER ORAL OR WRITTEN,
# * EXPRESS OR IMPLIED. THE AUTHOR SPECIFICALLY DISCLAIMS ANY IMPLIED
# * WARRANTIES OR CONDITIONS OF MERCHANTABILITY, SATISFACTORY QUALITY,
# * NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.

"""Binary Metadata"""

from cbc_sdk.errors import ObjectNotFoundError

METADATA_VALID = {
    'sha256': '0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc',
    'url': 'https://www.example.com',
    'architecture': ['amd64'],
    'available_file_size': 327680,
    'charset_id': 1200,
    'comments': None,
    'company_name': 'Microsoft Corporation',
    'copyright': '© Microsoft Corporation. All rights reserved.',
    'file_available': True,
    'file_description': 'Services and Controller app',
    'file_size': 327680,
    'file_version': '6.1.7601.24537 (win7sp1_ldr_escrow.191114-1547)',
    'internal_name': 'services.exe',
    'lang_id': 1033,
    'md5': '4b3a70e412a7a18a4dba277251e85bcf',
    'original_filename': 'services.exe',
    'os_type': 'WINDOWS',
    'private_build': None,
    'product_description': None,
    'product_name': 'Microsoft® Windows® Operating System',
    'product_version': '6.1.7601.24537',
    'special_build': None,
    'trademark': None
}

HASH_METADATA = {
    "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc": {
        "sha256": "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc",
        "architecture": [
            "amd64"
        ],
        "available_file_size": 327680,
        "charset_id": 1200,
        "comments": None,
        "company_name": "Microsoft Corporation",
        "copyright": "© Microsoft Corporation. All rights reserved.",
        "file_available": True,
        "file_description": "Services and Controller app",
        "file_size": 327680,
        "file_version": "6.1.7601.24537 (win7sp1_ldr_escrow.191114-1547)",
        "internal_name": "services.exe",
        "lang_id": 1033,
        "md5": "4b3a70e412a7a18a4dba277251e85bcf",
        "original_filename": "services.exe",
        "os_type": "WINDOWS",
        "private_build": None,
        "product_description": None,
        "product_name": "Microsoft® Windows® Operating System",
        "product_version": "6.1.7601.24537",
        "special_build": None,
        "trademark": None
    },
    "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4": {
        "sha256": "405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
        "architecture": [
            "amd64"
        ],
        "available_file_size": 46080,
        "charset_id": 1200,
        "comments": None,
        "company_name": "Microsoft Corporation",
        "copyright": "© Microsoft Corporation. All rights reserved.",
        "file_available": True,
        "file_description": "Windows host process (Rundll32)",
        "file_size": 46080,
        "file_version": "6.1.7601.23755 (win7sp1_ldr.170330-0600)",
        "internal_name": "rundll",
        "lang_id": 1033,
        "md5": "c36bb659f08f046b139c8d1b980bf1ac",
        "original_filename": "RUNDLL32.EXE",
        "os_type": "WINDOWS",
        "private_build": None,
        "product_description": None,
        "product_name": "Microsoft® Windows® Operating System",
        "product_version": "6.1.7601.23755",
        "special_build": None,
        "trademark": None
    },
    "e02d9989cbe295518350ed3f5a04a713ece692406a9ee354785c2a4078466dcd": ObjectNotFoundError
}
