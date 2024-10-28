# -*- coding: UTF-8 -*-
from .__common__ import API


__all__ = ["Maldatabase"]


class Maldatabase(API):
    doc = "https://maldatabase.com/api-doc.html"
    url = "https://api.maldatabase.com/download"
    _api_key_header = "Authorization"
    
    def get_malware_feed(self, hashtype="sha256"):
        # available output hash types: md5, sha1, sha256
        self._get("", headers={'Accept-Encoding': "gzip, deflate"})
        for data in self.json:
            yield data[hashtype]
