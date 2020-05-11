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

"""Base for ingestion component"""

import logging
import copy

from datetime import datetime
from .ubs import download_hashes, get_metadata

log = logging.getLogger(__name__)
log.disabled = False


class IngestionComponent:
    """
    IngestionComponent

    Description:
        Manages the fetching of the binary's metadata to send to the analysis engine(s)

    Args:
        config (Config): Config object.
        cb_threat_hunter (cbapi.CbThreatHunterAPI): Carbon Black ThreatHunter API object.
        state_manager (cbc_binary_toolkit.state.builtin.SQLiteBasedPersistor): State management object.

    Attributes:
        DEFAULT_EXPIRATION (int): How long generated binary AWS download links
            will stay valid, in seconds.

    """
    DEFAULT_EXPIRATION = 3600

    def __init__(self, config, cb_threat_hunter, state_manager):
        """Constructor"""
        self.config = config
        self.cb_threat_hunter = cb_threat_hunter
        self.state_manager = state_manager

    def reload(self):
        """
        Reloads unfinished binaries.

        Returns:
            List(Dict) of hash metadata.

        """
        engine_name = self.config.string("engine.name")
        unfinished_hashes = self.state_manager.get_unfinished_hashes(engine_name)

        return self.fetch_metadata(unfinished_hashes)

    def fetch_metadata(self, hashes):
        """
        Fetches the metadata and url for the binary

        Args:
            hashes (list): list of hashes to fetch

        Return:
            fetched_metadata = [{
               "sha256":"405f03534be8b45185695f68deb47d4daf04dcd6df9d351ca6831d3721b1efc4",
               "url": "AWS S3 AUTHORIZED URL",
               "architecture": [
                  "amd64"
               ],
               "available_file_size": int,
               "charset_id": int,
               "comments": str,
               "company_name": str,
               "copyright": str,
               "file_available": bool,
               "file_description": str,
               "file_size": int,
               "file_version": str,
               "internal_name": str,
               "lang_id": int,
               "md5": "c36bb659f08f046b139c8d1b980bf1ac",
               "original_filename": str,
               "os_type": "WINDOWS",
               "private_build": str,
               "product_description": str,
               "product_name": str,
               "product_version": str,
               "special_build": str,
               "trademark": str
            },
            ...
            ]

        """
        found = list()
        hashes_copy = copy.deepcopy(hashes)
        # Fetch download url from UBS
        while hashes_copy != []:
            found.extend(download_hashes(self.cb_threat_hunter,
                                         hashes_copy[:100],
                                         self.config.get("carbonblackcloud.expiration_seconds",
                                                         self.DEFAULT_EXPIRATION)))
            del hashes_copy[:100]

        engine_name = self.config.string("engine.name")
        fetched_metadata = list()

        # Fetch metadata from UBS
        for download_data in found:
            metadata = get_metadata(self.cb_threat_hunter, download_data)

            # Save hash entry to state manager
            if metadata:
                self.state_manager.set_checkpoint(download_data["sha256"],
                                                  engine_name,
                                                  "INGESTED")
                fetched_metadata.append(metadata)

        log.debug(f"Ingested: {datetime.now()}")
        return fetched_metadata
