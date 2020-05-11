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

"""Functions to retrieve binaries from Unified Binary Store"""

from cbapi.psc.threathunter.models import Binary, Downloads
import logging
import copy

log = logging.getLogger(__name__)


class RedownloadHashes:
    """
    Values and function to redownload any hashes that experienced an error during the initial download attempt.

    Args:
        cbth (cbapi.CbThreatHunterAPI): Carbon Black ThreatHunter object.
        shas (List[str]): hashes to be redownloaded.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Attributes:
        urlobject (str): Carbon Black Cloud Unified Binary Store API File Download route.
        RETRY_LIMIT (int): How many times to retry downloading from
            Carbon Black Cloud.

    """

    urlobject = "/ubs/v1/orgs/{}/file/_download"

    RETRY_LIMIT = 5

    def __init__(self, cbth, shas, expiration_seconds):
        """Redownload Hashes constructor"""
        self.cb = cbth
        self.shas = shas
        self.expiration_seconds = expiration_seconds
        self.found = []
        self.not_found = []
        self.attempt_num = 0

    def redownload(self):
        """Attempts to redownload hashes up to `RETRY_LIMIT` times before exiting."""
        body = {
            "sha256": self.shas,
            "expiration_seconds": self.expiration_seconds,
        }
        url = self.urlobject.format(self.cb.credentials.org_key)
        download = self.cb.post_object(url, body).json()
        self.attempt_num += 1
        # save any hashes found on the first retry
        if download["found"]:
            self.found = copy.deepcopy(download["found"])  # len 1

        if download["not_found"]:
            self.not_found = copy.deepcopy(download["not_found"])  # len 1

        while download["error"] and self.attempt_num < self.RETRY_LIMIT:
            body["sha256"] = copy.deepcopy(download["error"])
            download = self.cb.post_object(url, body).json()

            if download["found"]:
                self.found.extend(copy.deepcopy(download["found"]))

            if download["not_found"]:
                self.not_found.extend(copy.deepcopy(download["not_found"]))

            self.attempt_num += 1

        if self.attempt_num == self.RETRY_LIMIT and download["error"]:
            log.error(f"Reached retry limit for redownloading {len(download['error'])} hashes.")

        if self.not_found:
            log.warning(f"During retry, {len(self.not_found)} hashes were not found in "
                        f"the Unified Binary Store: {self.not_found}")


def _download_hashes(cbth, hashes, expiration_seconds):
    """
    Download hashes from Unified Binary Store.

    Args:
        cbth (cbapi.CbThreatHunterAPI): Carbon Black ThreatHunter object.
        hashes (List[str]): hashes to be downloaded from Unified Binary Store.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Returns:
        downloads: Downloads object with found, not_found, and error attributes.
        None if there is an error during download.

    """
    try:
        log.debug("Downloading hashes from Unified Binary Store")
        downloads = Downloads(cbth, hashes, expiration_seconds)
        return downloads
    except Exception as err:
        log.error(f"Error downloading hashes from Unified Binary Store: {err}")
        return None


def _download_binary_metadata(cbth, found_binary):
    """
    Retrieve metadata for a binary found in the Unified Binary Store.

    Args:
        cbth (cbapi.CbThreatHunterAPI): Carbon BlackThreatHunter object.
        found_binary (Dict): Dictionary with "sha256" and "url" values.

    Returns:
        binary_metadata (Dict): Metadata dictionary downloaded from Unified Binary Store.
        Empty dictionary if download for binary metadata failed.

    """
    if isinstance(found_binary, dict):
        try:
            log.debug("Downloading metadata information")
            binary_metadata = {"url": found_binary["url"]}
            th_binary = cbth.select(Binary, found_binary["sha256"])
            if isinstance(th_binary, Binary):
                binary_metadata.update(th_binary._info)
            return binary_metadata
        except Exception as err:
            log.error(f"Error downloading binary metadata from Unified Binary Store: {err}")
            return {}
    else:
        log.error("found_binary input to _download_binary_metadata must be a Dictionary with url and sha256 keys")
        return {}


def _validate_download(cbth, download, expiration_seconds):
    """
    Verifies the presence of Downloads.FoundItem. Retries downloading if there are errors during download.

    Args:
        cbth (CbThreatHunterAPI): Carbon BlackThreatHunter object.
        download (ThreatHunter.Downloads): May contain found, not_found, and error attributes.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Returns:
        (download_found, redownload.found) (List[dict], List[dict]): A tuple of downloaded and
            redownloaded hashes. Second return value may be none if there were no hashes to re-download,
            or re-downloading timed out.
        (None, None) if no hashes were successfully downloaded and re-downloaded.

    """
    if not download:
        log.error("No hashes were found in the Unified Binary Store.")
        return None, None

    if download.not_found:
        log.warning(f"{len(download.not_found)} hashes were not found in the"
                    f" Unified Binary Store: {download.not_found}")

    download_found = download._info["found"]
    redownload = None
    if download.error:
        log.warning(f"{len(download.error)} hashes experienced an error while"
                    f" downloading: {download.error}. Retrying download.")

        redownload = RedownloadHashes(cbth, [download.error], expiration_seconds)

        redownload.redownload()

        return download_found, redownload.found

    return download_found, redownload


def download_hashes(cbth, hashes, expiration_seconds=3600):
    """
    Initiates download of hashes

    Args:
        cbth (cbapi.CbThreatHunterAPI): Carbon BlackThreatHunter object.
        hashes (List[str]): hashes to be downloaded from Unified Binary Store.
        expiration_seconds (int, optional): Desired timeout for AWS links to binaries.

    Returns:
        found_hashes (List[Dict]): found hashes and their download URLs.
        Empty list if an error occurred during download.

    Examples:
        >>> download_hashes(cbth, ["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])

    """
    if not hashes:
        log.error("No hashes supplied to download_hashes.")
        return list()
    download = _download_hashes(cbth, hashes, expiration_seconds)

    checked_download, retried_download = _validate_download(cbth, download, expiration_seconds)

    if not checked_download:
        log.error("Unable to retrieve binaries from the Unified Binary Store.")

    if retried_download:
        found_hashes = checked_download + retried_download
    else:
        found_hashes = checked_download

    if found_hashes is None:
        found_hashes = list()
    return found_hashes


def get_metadata(cbth, binary):
    """
    Initiates download of binary metadata from Unified Binary Store.

    Args:
        cbth (cbapi.CbThreatHunterAPI): Carbon Black ThreatHunter object.
        binary (Dict): Dictionary with "sha256" and "url" values.

    Returns:
        metadata (Dict): Dictionary containing hash, download URL, and metadata.

    """
    if not binary:
        log.error("Received empty binary object.")
        return {}
    else:
        try:
            return _download_binary_metadata(cbth, binary)
        except Exception as err:
            log.error(f"Failed to download metadata: {err}")
            return {}
