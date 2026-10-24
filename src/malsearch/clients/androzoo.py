# -*- coding: UTF-8 -*-
from threading import BoundedSemaphore

from .__common__ import hashtype, API


__all__ = ["AndroZoo"]


class AndroZoo(API):
    doc = "https://androzoo.uni.lu/api_doc"
    url = "https://androzoo.uni.lu/api"
    _api_key_param = "apikey"
    _invalid_key = lambda s, r: r.status_code == 403 or r.status_code == 400 and "invalid apikey" in r.text.lower()
    _slots = BoundedSemaphore(20)  # AndroZoo asks for at most ~20 concurrent downloads

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        with AndroZoo._slots:
            self._get("download", params={'sha256': hash})._save()
