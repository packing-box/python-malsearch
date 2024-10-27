# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["VirusShare"]


class VirusShare(API):
    doc = "https://virusshare.com/apiv2_reference"
    url = "https://virusshare.com/apiv2"
    _api_key_param = "apikey"
    
    @hashtype("md5", "sha1", "sha224", "sha256", "sha384", "sha512")
    def get_file_by_hash(self, hash):
         self._get("download", params={'hash': hash})._save(hash)
