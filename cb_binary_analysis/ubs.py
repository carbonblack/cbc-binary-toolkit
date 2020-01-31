# -*- coding: utf-8 -*-

"""
Functions to retrieve binaries from UBS
"""

from dataclasses import dataclass
#from main import config
import json
import requests
import logging


log = logging.getLogger(__name__)


@dataclass
class Binary:
    """
    Represents a retrievable binary.
    """
    sha256: str
    url: str


class Downloads(Binary):
    """
    Represents download information for a list of process hashes.
    """

    class FoundItem(Binary):
        """
        Represents the download URL and process hash for a successfully
        located binary.
        """
        def __init__(self, item):
            super(Downloads.FoundItem, self).__init__(item["sha256"], item["url"])

    class NotFoundItem(Binary):
        """
        Represents the process hash for an unsuccessfully
        located binary.
        """
        def __init__(self, item):
            super(Downloads.NotFoundItem, self).__init__(item, None)

    class Errored(Binary):
        """
        Represents the process hash for an unsuccessfully
        located binary.
        """
        def __init__(self, item):
            super(Downloads.Errored, self).__init__(item, None)

    def __init__(self, sha_dict):
        self.body = json.dumps(sha_dict)
        self.headers = {'Content-type': 'application/json',
                        'X-Auth-Token': '8NZIDZMHIFW4QLAFC52ZZCFH/BI61IM2YSW'
                        }

        #url = f'{config.url}/ubs/v1/orgs/{config.org_key}/file/_download'
        #self.token = config.token
        #self.token_header = {'X-Auth-Token': self.token, 'User-Agent': None}

        self.myurl = 'https://defense-eap01.conferdeploy.net'
        self.myorg_key = 'WNEXFKQ7'
        self.url = f'{self.myurl}/ubs/v1/orgs/{self.myorg_key}/file/_download'
        self.session = requests.Session()
        self.r = self.session.request("POST", self.url, headers=self.headers,
                                      data=self.body).json()

    def download(self, shas, expiration_seconds=3600):
        """
        Can be used to re-download hashes that had an issue during
        initial download
        """
        body = {
            "sha256": shas,
            "expiration_seconds": expiration_seconds
        }
        r = self.session.request("POST", self.url, headers=self.headers,
                                 data=body).json()
        return r

    @property
    def found(self):
        """
        Returns a list of Downloads.FoundItem, one
        for each binary found in the binary store.
        """
        return [Downloads.FoundItem(item) for item in self.r['found']]

    @property
    def not_found(self):
        """
        Returns a list of Downloads.NotFoundItem, one
        for each binary not found in the binary store.
        """
        return [Downloads.NotFoundItem(item) for item in self.r['not_found']]

    @property
    def errored_out(self):
        """
        Returns a list of Downloads.Errored, one
        for each binary submitted to the UBS that
        had an intermittent error.
        """
        return [Downloads.Errored(item) for item in self.r['error']]


sha_dict = {"sha256": ["6c4eb3c9e0f478b2d19a329687d113ba92c90a17d0caa6c40247a5afff31f0cd", "0995f71c34f613207bc39ed4fcc1bbbee396a543fa1739656f7ddf70419309fc"], "expiration_seconds": 3600 }
download_0 = Downloads(sha_dict)
found = download_0.found
print(found)
not_found = download_0.not_found
print(not_found)
errored = download_0.errored_out
print(errored)

if errored:
    retry = download_0.download(shas=[item["sha256"] for item in download_0.errored_out])
    print(retry)
