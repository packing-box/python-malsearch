# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["MalShare"]


class MalShare(API):
    doc = "https://malshare.com/doc.php"
    url = "https://malshare.com"
    _api_key_param = "api_key"
    # an invalid key gives 400 ("User specified in `api_key` GET variable does not exist")
    _invalid_key = lambda s, r: r.status_code in (401, 403) or r.status_code == 400 and "does not exist" in r.text
    
    def get_malware_feed(self):
        # hashes of the past 24 hours
        self._get("api.php", params={'action': "getlist"})
        if isinstance(data := getattr(self, "json", None), list):
            for sample in data:
                if isinstance(sample, dict) and sample.get('sha256'):
                    yield sample['sha256'].lower()
    
    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        self._get("api.php", params={'action': "getfile", 'hash': hash})._save()

