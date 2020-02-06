# -*- coding: utf-8 -*-


"""
Functions to retrieve binaries from UBS
"""

from cbapi.psc.threathunter.models import Binary, Downloads
from cbapi.psc.threathunter import CbThreatHunterAPI
from .config.model import Config
import logging
from time import sleep

log = logging.getLogger(__name__)


def _create_cbth(args):
    """Generates a CbThreatHunterAPI object to use in other functions"""
    try:
        cbth = CbThreatHunterAPI(url=args['url'], token=args['apitoken'], ssl_verify=args['ssl_verify'], org_key=args['orgkey'])
    except Exception as err:
        log.error(f"Failed to create a CbThreatHunterAPI object. Exiting. {err}")
        raise
    return cbth


def _download_hashes(cbth, hashes, expiration_seconds=60):
    """Download hashes from UBS"""
    try:
        log.debug("Downloading hashes from UBS")
        downloads = Downloads(cbth, hashes, expiration_seconds)
        return downloads
    except Exception as err:
        log.error(f"Error downloading hashes from UBS: {err}")
        return


def _download_hash_metadata(cbth, downloads):
    """Retrieve metadata for each found hash"""
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


def _retry_download(cbth, hashes_with_download_errors, attempt_num):
    """Retries to download any hashes that errored out while downloading."""
    downloaded_hashes = []
    print(f"Attempt {attempt_num} to re-download {hashes_with_download_errors}.")
    if attempt_num > 5:
        log.debug("Reached retry limit for downloading hashes that experienced an error during download")
    else:
        downloaded_hashes = _download_hashes(cbth, hashes_with_download_errors)
    return downloaded_hashes, attempt_num + 1


def _check_download(cbth, download, attempt_num):
    """
    Verifies the presence of Downloads.FoundItem. Retries downloading
    if there are errors during download.
    """
    if not download:
        log.error("No hashes were found in the Universal Binary Store.")
        return

    if download.not_found:
        log.warning(f"{len(download.not_found)} hashes were not found in the Universal Binary Store: {download.not_found}")

    # if download.found and attempt_num == 1:  # download.error:
    if download.error:
        log.warning(f"{len(download.error)} hashes experienced an error while downloading: {download.error}. Retrying download.")

        retry, attempt = _retry_download(cbth, download.error, attempt_num)
        # retry, attempt = _retry_download(cbth, ["0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"], attempt_num)
        sleep(2)

        retry_check = _check_download(cbth, retry, attempt)

        if retry_check:
            return download, retry

    if download:
        return download


def download(hashes):
    """Initiates download of hashes and their metadata"""
    config = Config.load_file('/Users/llyon/reno/dev/cb-binary-analysis/config/binary-analysis-config.yaml')

    cbth = _create_cbth(config._data['carbonblackcloud'])

    downloaded_hashes = _download_hashes(cbth, hashes)

    found_hashes = _check_download(cbth, downloaded_hashes, attempt_num=1)

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
        # log.debug("No hashes errored out while downloading.")
        metadata.append(_download_hash_metadata(cbth, found_hashes.found))
    print(f"len {len(metadata)} Metadata from input: {metadata}")
    return metadata


# download(["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd", "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"])
