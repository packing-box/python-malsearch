# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["MalShare"]


class MalShare(API):
    doc = "https://malshare.com/doc.php"
    url = "https://malshare.com"
    _api_key_param = "api_key"

    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        self._get("api.php", params={'action': "getfile", 'hash': hash})._save(hash)
