# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API, HashNotFoundError


__all__ = ["URLhaus"]


class URLhaus(API):
    doc = "https://urlhaus-api.abuse.ch"
    url = "https://urlhaus-api.abuse.ch/v1"
    _api_key_header = "Auth-Key"
    # missing key gives 401 while an unknown key gives 403 ("unknown_auth_key")
    _invalid_key = lambda s, r: r.status_code in (401, 403)

    def get_malware_feed(self):
        # payloads from the past 3 days (at most 1000)
        self._get("payloads/recent/limit/1000/")
        for payload in getattr(self, "json", {}).get('payloads') or []:
            yield payload['sha256_hash']

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        self._get(f"download/{hash}/")
        # anything else than a ZIP means that the payload was not found (or could not be copied)
        if getattr(self, "content", b"")[:2] != b"PK":
            raise HashNotFoundError(hash, self.__class__.__name__)
        self._unzip(b"infected")._save()
