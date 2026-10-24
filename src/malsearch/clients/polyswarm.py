# -*- coding: UTF-8 -*-
from .__common__ import _hash_type, hashtype, API


__all__ = ["PolySwarm"]


class PolySwarm(API):
    doc = "https://github.com/polyswarm/polyswarm-api"
    url = "https://api.polyswarm.network/v3"
    _api_key_header = "Authorization"
    # missing or wrong key gives 401 while a malformed key gives 400 ("API Key must be a 32 character ...")
    _invalid_key = lambda s, r: r.status_code in (401, 403) or r.status_code == 400 and "api key" in r.text.lower()
    # 204 (No Content) is returned when there is no result for the hash
    _post_condition = lambda s: len(getattr(s, "content", b"")) > 0

    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        self._get(f"consumer/download/{_hash_type(hash)}/{hash}", params={'community': "default"})._save()
