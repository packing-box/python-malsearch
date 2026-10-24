# -*- coding: UTF-8 -*-
import hashlib

from .__common__ import _hash_type, hashtype, API, HashNotFoundError, ServiceUnavailable


__all__ = ["AnyRun"]


class AnyRun(API):
    doc = "https://any.run/api-documentation/"
    url = "https://api.any.run/v1"
    _auth_method = "API-Key"
    # an invalid key gives 401 (TI Lookup) or 403 (Sandbox) while a missing or expired TI license gives 402
    _invalid_key = lambda s, r: r.status_code in (401, 402, 403)

    def _link(self, hash):
        """ Get the download link of the given sample from TI Lookup, either directly from the files seen in tasks or
             from the report of a task whose main object is the sample. """
        htype = _hash_type(hash)
        match = lambda o: isinstance(o, dict) and str((o.get('hashes') or {}).get(htype, "")).lower() == hash
        self._post("intelligence/api/search", json={'query': hash})
        data = getattr(self, "json", {})
        for f in data.get('relatedFiles') or []:
            if match(f) and f.get('fileLink'):
                return f['fileLink']
        for t in data.get('sourceTasks') or []:
            if isinstance(t, dict) and match(t.get('mainObject')) and t.get('uuid'):
                self._get(f"analysis/{t['uuid']}")
                obj = (((getattr(self, "json", {}).get('data') or {}).get('analysis') or {}).get('content') or {}) \
                      .get('mainObject')
                if match(obj) and obj.get('permanentUrl'):
                    return obj['permanentUrl']
        raise HashNotFoundError(hash, self.__class__.__name__)

    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        from urllib.parse import urlparse
        from requests import exceptions, get
        # requires a TI Lookup license
        link = self._link(hash)
        # files are private content, hence the API key is required ; never send it to another host than ANY.RUN's
        if urlparse(link).scheme != "https" or not (urlparse(link).hostname or "").endswith(".any.run"):
            raise ServiceUnavailable(self.__class__.__name__, "unexpected download link")
        try:
            r = get(link, headers={'Authorization': f"{self._auth_method} {self._api_key}"})
            r.raise_for_status()
        except exceptions.RequestException as e:
            raise ServiceUnavailable(self.__class__.__name__, e.__class__.__name__)
        self.content = r.content
        # the sample may come zipped (password "infected") ; do not unzip it if it is already the sample itself
        #  (e.g. an APK, which is a ZIP)
        if hashlib.new(_hash_type(hash), self.content).hexdigest() != hash and self.content[:2] == b"PK":
            self._unzip(b"infected")
        self._save()
