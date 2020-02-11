# -*- coding: utf-8 -*-


"""
Functions to retrieve binaries from UBS
"""

from cbapi.psc.threathunter.models import Binary, Downloads
from cbapi.psc.threathunter import CbThreatHunterAPI
from .config.model import Config
import logging
import os

log = logging.getLogger(__name__)


class redownloadHashes:
    """Values and function to redownload any hashes that experienced an error
    during the initial download attempt.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        shas (List[str]): hashes to be redownloaded.
        expiration_seconds (int): Desired timeout for AWS links to binaries.
    """

    urlobject = "/ubs/v1/orgs/{}/file/_download"

    def __init__(self, cbth, shas, expiration_seconds):
        self.cb = cbth
        self.shas = shas
        self.expiration_seconds = expiration_seconds
        self.found = []

    def redownload(self):
        """Attempts to redownload hashes up to five times before exiting."""
        body = {
            "sha256": self.shas,
            "expiration_seconds": self.expiration_seconds,
        }
        url = self.urlobject.format(self.cb.credentials.org_key)  # need an org key from config here
        download = self.cb.post_object(url, body).json()

        # save any hashes found on the first retry
        if download["found"]:
            self.found = download["found"]

        attempt_num = 1
        while download["error"] and attempt_num < 5:
            body["sha256"] = download["error"]
            download = self.cb.post_object(url, body).json()

            if download["found"]:
                self.found.append(download["found"])

            attempt_num += 1

        if attempt_num == 5 and download["error"]:
            log.error(f"Reached retry limit for redownloading {len(download['error'])} hashes.")


def _create_cbth(args):
    """Generates a CbThreatHunterAPI object to use in other functions."""
    try:
        cbth = CbThreatHunterAPI(url=args['url'], token=args['apitoken'],
                                 ssl_verify=args['ssl_verify'], org_key=args['orgkey'])
    except Exception as err:
        log.error(f"Failed to create a CbThreatHunterAPI object. Exiting. {err}")
        raise
    return cbth


def _download_hashes(cbth, hashes, expiration_seconds):
    """Download hashes from UBS.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        hashes (List[str]): hashes to be downloaded from UBS.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Returns:
        downloads: Downloads object with found, not_found, and error attributes.
        None if there is an error during download.
    """
    try:
        log.debug("Downloading hashes from UBS")
        downloads = Downloads(cbth, hashes, expiration_seconds)
        return downloads
    except Exception as err:
        log.error(f"Error downloading hashes from UBS: {err}")
        return


def _download_binary_metadata(cbth, found_binary):
    """Retrieve metadata for a binary found in the UBS.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        found_binary (Dict): Dictionary with "sha256" and "url" values.

    Returns:
        binary_metadata (Dict): Metadata dictionary downloaded from UBS.
        None if download for binary metadata failed.
    """
    if found_binary:
        try:
            log.debug("Downloading metadata information")
            binary_metadata = {"url": found_binary["url"]}   # was JSON in _initial_data or _info
            th_binary = cbth.select(Binary, found_binary["sha256"])
            if isinstance(th_binary, Binary):
                binary_metadata.update(th_binary._info)
            return binary_metadata
        except Exception as err:
            log.error(f"Error downloading binary metadata from UBS: {err}")
            return
    else:
        return


def _validate_download(cbth, download, attempt_num, expiration_seconds):
    """
    Verifies the presence of Downloads.FoundItem. Retries downloading
    if there are errors during download.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        download (ThreatHunter.Downloads): May contain found, not_found, and error attributes.
        attempt_num (int): Number of times we've tried downloading these hashes.
            Limit is set to 5 times.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Returns:
        (download_found, redownload.found) (List[str], List[str]): A tuple of lists.
            Second return value may be none if there were no hashes to re-download,
            or re-downloading timed out.
        None if no hashes were successfully downloaded.
    """
    if not download:
        log.error("No hashes were found in the Universal Binary Store.")
        return

    if download.not_found:
        log.warning(f"{len(download.not_found)} hashes were not found in the"
                    f" Universal Binary Store: {download.not_found}")

    download_found = download._info["found"]
    redownload = None
    if download.error:
        log.warning(f"{len(download.error)} hashes experienced an error while"
                    f" downloading: {download.error}. Retrying download.")

        redownload = redownloadHashes(cbth, download.error, expiration_seconds)

        redownload.redownload()

        return download_found, redownload.found

    return download_found, redownload


def download_hashes(hashes, expiration_seconds=3600):
    """Initiates download of hashes.

    Args:
        hashes (List[str]): hashes to be downloaded from UBS.
        expiration_seconds (int, optional): Desired timeout for AWS links to binaries.

    Returns:
        found_hashes (List[Dict]): found hashes and their download URLs.
        None if an error occurred during download.

    Examples:
        >>> download_hashes(["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])
    """

    config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../config/binary-analysis-config.yaml")
    config = Config.load_file(config_path)

    cbth = _create_cbth(config._data['carbonblackcloud'])

    download = _download_hashes(cbth, hashes, expiration_seconds)

    checked_download, retried_download = _validate_download(cbth, download, 1, expiration_seconds)

    if not checked_download:
        log.error("Unable to retrieve binaries from the UBS.")

    if retried_download:
        found_hashes = checked_download + retried_download
    else:
        found_hashes = checked_download
    return found_hashes


def get_metadata(cbth, binary):
    """Initiates download of binary metadata from UBS.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        binary (Dict): Dictionary with "sha256" and "url" values.
    Returns:
        metadata (Dict): Dictionary containing hash, download URL, and metadata.
    """

    metadata = None
    try:
        metadata = _download_binary_metadata(cbth, binary)
    except Exception as err:
        log.error(f"Failed to download metadata for {binary.sha256}: {err}")
    return metadata
