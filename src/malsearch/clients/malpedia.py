# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["Malpedia"]


class Malpedia(API):
    doc = "https://malpedia.caad.fkie.fraunhofer.de/usage/api"
    url = "https://malpedia.caad.fkie.fraunhofer.de/api"
    _auth_method = "APIToken"

    @hashtype("md5", "sha256")
    def get_file_by_hash(self, hash):
        self._get(f"get/sample/{hash}/zip")._save(hash)
        #TODO: parse ZIP for unpacked version
