# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["VirusTotal"]


class VirusTotal(API):
    doc = "https://docs.virustotal.com/reference/overview"
    url = "https://www.virustotal.com/api/v3"
    _api_key_header = "x-apikey"
    # an invalid key gives 401 (WrongCredentialsError) while a key without download privilege gives 403
    _invalid_key = lambda s, r: r.status_code in (401, 403)
    
    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        if getattr(self, "_unpacked", False):
            self._get(f"files/{hash}")
            for n in self.json['data']['attributes'].get('names', []):
                if n.endswith("_unpacked"):
                    hash2, _ = n.split("_", 1)
                    self._get(f"files/{hash2}/download")._save(hash2)
        # raw file, unless it comes zipped
        self._get(f"files/{hash}/download")._extract(b"infected")._save()

