# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API, HashNotFoundError, ServiceUnavailable


__all__ = ["MetaDefender"]


class MetaDefender(API):
    doc = "https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4"
    url = "https://api.metadefender.com/v4"
    _api_key_header = "apikey"
    # a missing or invalid key gives 401 ({"error": {"code": 401000, "messages": ["Unauthorized"]}}) ; 403 is assumed
    #  to mean that the key lacks the privilege (sample sharing is reserved to partners of the malware exchange program)
    _invalid_key = lambda s, r: r.status_code in (401, 403)

    def get_malware_feed(self):
        # infected hashes of the last 30 days (requires a license with feed access)
        self._get("feed/infected/latest")
        for h in getattr(self, "json", {}).get('hashes') or []:
            if isinstance(h, dict) and h.get('sha256'):
                yield h['sha256'].lower()

    @hashtype("md5", "sha1", "sha256")
    def get_file_by_hash(self, hash):
        # only available to the partners of OPSWAT's malware exchange program
        self._get(f"file/{hash}/download")
        # the API returns a download link ; the field name is not documented
        data = getattr(self, "json", None)
        link = next((v for k in ["url", "download_url", "link", "download_link"]
                     if isinstance(data, dict) and isinstance(v := data.get(k), str) and v.startswith("http")), None)
        if link is None:
            raise HashNotFoundError(hash, self.__class__.__name__)
        from requests import exceptions, get
        try:
            # pre-signed link, hence no API key
            r = get(link)
            r.raise_for_status()
        except exceptions.RequestException as e:
            raise ServiceUnavailable(self.__class__.__name__, e.__class__.__name__)
        self.content = r.content
        # MetaDefender Cloud does not store the files of an archive separately, hence the downloaded file may be an
        #  archive that contains the sample
        self._extract(b"infected")._save()
