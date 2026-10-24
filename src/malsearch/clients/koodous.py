# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API, HashNotFoundError, ServiceUnavailable


__all__ = ["Koodous"]


class Koodous(API):
    doc = "https://docs.koodous.com/api/apks.html"
    url = "https://developer.koodous.com"
    _auth_method = "Token"
    # an invalid token gives 401 ({"detail": "Invalid token."})
    _invalid_key = lambda s, r: r.status_code in (401, 403)

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        # downloads per day: 0 (Free API), 15 (Fan), 300 (Research), 5000 (Corporate)
        self._get(f"apks/{hash}/download/")
        # the API returns a download link valid for 3 minutes ; the field name is not documented
        data = getattr(self, "json", None)
        link = next((v for k in ["download_url", "url", "link", "download_link"]
                     if isinstance(data, dict) and isinstance(v := data.get(k), str) and v.startswith("http")), None)
        if link is None:
            raise HashNotFoundError(hash, self.__class__.__name__)
        from requests import exceptions, get
        try:
            # pre-signed link, hence no Authorization header
            r = get(link)
            r.raise_for_status()
        except exceptions.RequestException as e:
            raise ServiceUnavailable(self.__class__.__name__, e.__class__.__name__)
        self.content = r.content
        self._save()
