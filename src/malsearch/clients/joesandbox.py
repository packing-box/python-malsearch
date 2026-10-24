# -*- coding: UTF-8 -*-
import hashlib

from .__common__ import _hash_type, hashtype, API, HashNotFoundError


__all__ = ["JoeSandbox"]


class JoeSandbox(API):
    doc = "https://github.com/joesecurity/jbxapi"
    url = "https://jbxcloud.joesecurity.org/api/v2"
    # errors look like {"errors": [{"code": 4, "message": "Invalid API key"}]} with 403 for an invalid key

    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        # the API key is sent in the form data of every (POST) request
        self._post("analysis/search", data={'apikey': self._api_key, 'q': hash})
        # the search also matches filenames, comments, URLs, ... hence only keep analyses of the exact sample
        htype = _hash_type(hash)
        webid = next((a['webid'] for a in getattr(self, "json", {}).get('data') or []
                      if isinstance(a, dict) and str(a.get(htype, "")).lower() == hash and a.get('webid')), None)
        if webid is None:
            raise HashNotFoundError(hash, self.__class__.__name__)
        self._post("analysis/download", data={'apikey': self._api_key, 'webid': webid, 'type': "sample"})
        # the sample may come zipped (password "infected") ; do not unzip it if it is already the sample itself
        #  (e.g. an APK, which is a ZIP)
        content = getattr(self, "content", b"")
        if hashlib.new(htype, content).hexdigest() != hash and content[:2] == b"PK":
            self._unzip(b"infected")
        self._save()
