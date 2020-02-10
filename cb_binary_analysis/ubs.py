# -*- coding: utf-8 -*-


"""
Functions to retrieve binaries from UBS
"""

from cbapi.psc.threathunter.models import Binary, Downloads
from cbapi.psc.threathunter import CbThreatHunterAPI
from config.model import Config
import logging

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


def _download_binary_metadata(cbth, found_binary):
    """Retrieve metadata for a binary found in the UBS.

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        found_binary (ThreatHunter.models.Downloads): Binary to get metadata for.

    Returns:
        metadata_list (Dict): Metadata dictionary downloaded from UBS.
        None if metadata download for binary metadata failed.
    """
    if found_binary:
        try:
            log.debug("Downloading metadata information")
            binary_metadata = found_binary._info
            binary_metadata.pop('not_found')
            binary_metadata.pop('error')
            th_binary = cbth.select(Binary, found_binary.found[0].sha256)
            if isinstance(th_binary, Binary):
                binary_metadata.update(th_binary._info)
            return binary_metadata
        except Exception as err:
            log.error(f"Error downloading binary metadata from UBS: {err}")
            return
    else:
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
    downloaded_hashes = None
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
        (download, retry): A tuple of Downloads objects. Value of retry is None
            if there were no hashes to re-download, or re-downloading timed out.
        None if no hashes were successfully downloaded.
    """
    if not download:
        log.error("No hashes were found in the Universal Binary Store.")
        return

    if download.not_found:
        log.warning(f"{len(download.not_found)} hashes were not found in the Universal Binary Store: {download.not_found}")

    retry = None
    if download.error:
        log.warning(f"{len(download.error)} hashes experienced an error while downloading: {download.error}. Retrying download.")

        retry, attempt = _retry_download(cbth, download.error, attempt_num, expiration_seconds)

        while retry.error and attempt < 5:
            retry, attempt = _retry_download(cbth, retry.error, attempt_num, expiration_seconds)
            attempt_num += 1

    if download:
        return download, retry


def download_hashes(hashes, expiration_seconds=3600):
    """Initiates download of hashes.

    Args:
        hashes (List[str]): hashes to be downloaded from UBS.
        expiration_seconds (int, optional): Desired timeout for AWS links to binaries.

    Returns:
        checked_hashes, retry: A tuple of Downloads objects. Value of retry is None
            if there were no hashes to re-download, or re-downloading timed out.
        None if no binaries could be found or downloaded.

    Examples:
        >>> download(["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])
    """
    config = Config.load_file('/Users/llyon/reno/dev/cb-binary-analysis/config/binary-analysis-config.yaml')

    cbth = _create_cbth(config._data['carbonblackcloud'])

    downloaded_hashes = _download_hashes(cbth, hashes, expiration_seconds)

    checked_hashes, retry = _check_download(cbth, downloaded_hashes, 1, expiration_seconds)

    if not checked_hashes:
        log.error("Unable to retrieve binaries from the UBS.")

    return checked_hashes, retry


def get_metadata(cbth, binary):
    """Initiates download of binary metadata from UBS

    Args:
        cbth (CbThreatHunterAPI): CB ThreatHunter object.
        binary (ThreatHunter.Downloads): Should contain found, may also contain not_found, and error attributes.

    Returns:
        metadata (Dict): Dictionary containing hash, download URL, and metadata for given binary.
    """

    metadata = None
    try:
        metadata = _download_binary_metadata(cbth, binary)
    except Exception as err:
        log.error(f"Failed to download metadata for {binary.found[0].sha256}: {err}")

    return metadata
