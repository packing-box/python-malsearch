# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["Triage"]


class Triage(API):
    doc = "https://tria.ge/docs"
    url = "https://tria.ge/api/v0"
    _auth_method = "Bearer"

    @hashtype("md5", "sha1", "sha256", "sha512")
    def get_file_by_hash(self, hash):
        hashtype = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}[len(hash)]
        self._get("search", params={'query': f"{hashtype}:{hash}"})
        try:
            sample_id = self.json['data'][0]['id']
            self._get(f"samples/{sample_id}/sample")._save(hash)
        except IndexError:
            delattr(self, "content")
