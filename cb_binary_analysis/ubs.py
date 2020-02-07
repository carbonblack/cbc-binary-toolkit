# -*- coding: utf-8 -*-


"""
Functions to retrieve binaries from UBS
"""

from cbapi.psc.threathunter.models import Binary, Downloads
from cbapi.psc.threathunter import CbThreatHunterAPI
from config.model import Config
import logging
from time import sleep

log = logging.getLogger(__name__)


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
        downloads: Downloads object, with found, not_found, and error attributes.
        None if there is an error during download.
    """
    try:
        log.debug("Downloading hashes from UBS")
        downloads = Downloads(cbth, hashes, expiration_seconds)
        return downloads
    except Exception as err:
        log.error(f"Error downloading hashes from UBS: {err}")
        return


def _download_hash_metadata(cbth, downloads):
    """Retrieve metadata for each found hash.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        downloads (List[ThreatHunter.models.Downloads.FoundItem]): Hashes to get metadata for.

    Returns:
        metadata_list (List[Dict]): List of metadata dictionaries downloaded
            from UBS, one dictionary for each hash.
        None if metadata downloads for all hashes failed.
    """
    metadata_list = []
    try:
        log.debug("Downloading metadata information")
        for download in downloads:
            binary_metadata = download._info
            th_binary = cbth.select(Binary, download.sha256)
            if isinstance(th_binary, Binary):
                binary_metadata.update(th_binary._info)

            metadata_list.append(binary_metadata)
        return metadata_list
    except Exception as err:
        log.error(f"Error downloading hash metadata from UBS: {err}")
    return


def _retry_download(cbth, hashes_with_download_errors, attempt_num, expiration_seconds):
    """Retries to download any hashes that errored out while downloading.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        hashes_with_download_errors (List[str]): Hashes that errored during
            a previous download attempt.
        attempt_num (int): Number of times we've tried downloading these hashes.
            Limit is set to 5 times.
        expiration_seconds (int): Desired timeout for AWS links to binaries.

    Returns:
        (downloaded_hashes, attempt_num+1) if the hashes were successfully re-downloaded.
        (None, attempt_num+1) if the hashes couldn't be re-downloaded.
    """
    downloaded_hashes = []
    if attempt_num > 5:
        log.debug("Reached retry limit for downloading hashes that experienced an error during download")
    else:
        log.debug(f"Attempt {attempt_num} to re-download {hashes_with_download_errors}.")
        downloaded_hashes = _download_hashes(cbth, hashes_with_download_errors, expiration_seconds)
    return downloaded_hashes, attempt_num + 1


def _check_download(cbth, download, attempt_num, expiration_seconds):
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
        download: Downloads object that may have found, not_found, and/or error attributes
        (download, retry): A tuple of Downloads objects. This happens if there were
            hashes that errored during download, and were successfully re-downloaded.
        None if no hashes were successfully downloaded.
    """
    if not download:
        log.error("No hashes were found in the Universal Binary Store.")
        return

    if download.not_found:
        log.warning(f"{len(download.not_found)} hashes were not found in the Universal Binary Store: {download.not_found}")

    if download.error:
        log.warning(f"{len(download.error)} hashes experienced an error while downloading: {download.error}. Retrying download.")

        retry, attempt = _retry_download(cbth, download.error, attempt_num, expiration_seconds)
        sleep(2)

        retry_check = _check_download(cbth, retry, attempt, expiration_seconds)

        if retry_check:
            return download, retry

    if download:
        return download


def download(hashes, expiration_seconds=3600):
    """Initiates download of hashes and their metadata

    Args:
        hashes (List[str]): hashes to be downloaded from UBS.
        expiration_seconds (int, optional): Desired timeout for AWS links to binaries.

    Returns:
        metadata (List[List[Dict]]): Metadata downloaded from UBS for any hashes
            downloaded or re-downloaded. Will contain one list of dictionaries if
            downloading was successful first try, or two lists of dictionaries if
            re-downloading was tried and successful.
        None if no hashes could be downloaded.

    Examples:
        >>> download(["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])
        {'sha256': '0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc', 'url': [...], 'architecture':...}
    """
    config = Config.load_file('/Users/llyon/reno/dev/cb-binary-analysis/config/binary-analysis-config.yaml')

    cbth = _create_cbth(config._data['carbonblackcloud'])

    downloaded_hashes = _download_hashes(cbth, hashes, expiration_seconds)

    found_hashes = _check_download(cbth, downloaded_hashes, 1, expiration_seconds)

    if not found_hashes:
        log.error("Unable to retrieve hashes and metadata.")
        return

    metadata = []

    if isinstance(found_hashes, tuple):
        log.debug("Successfully re-downloaded hashes that errored out during download.")
        for item in found_hashes:
            try:
                hash_metadata = _download_hash_metadata(cbth, item.found)
                metadata.append(hash_metadata[0])
            except Exception as err:
                log.error(f"Failed to download metadata for {item.found[0].sha256}: {err}")

    else:
        metadata.append(_download_hash_metadata(cbth, found_hashes.found))
    print(f"len {len(metadata)} Type {type(metadata[0])} Metadata from input: {metadata}")
    return metadata
