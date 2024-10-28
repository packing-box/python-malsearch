# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["VirusTotal"]


class VirusTotal(API):
    doc = "https://docs.virustotal.com/reference/overview"
    url = "https://www.virustotal.com/api/v3"
    _api_key_header = "X-Apikey"
    
    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        if self._unpacked:
            data = self._get(f"/files/{hash}")
            for n in data['data']['attributes']['names']:
                if n.endswith("_unpacked"):
                    hash2, _ = n.split("_", 1)
                    self._get(f"/files/{hash2}/download")._save(hash2)
        self._get(f"files/{hash}/download")._unzip(b"infected")._save(hash)
