# -*- coding: UTF-8 -*-
from .__common__ import hashtype, logger, API, HashNotFoundError, ServiceUnavailable


__all__ = ["UnpacMe"]


class UnpacMe(API):
    doc = "https://api.unpac.me/openapi.json"
    url = "https://api.unpac.me/api/v1"
    _auth_method = "Key"
    # a missing or invalid key gives 401 ({"description": "Unable to parse authentication token.", ...})
    _invalid_key = lambda s, r: r.status_code in (401, 403)
    _poll_interval = 2   # seconds between two checks of a batch download job
    _poll_timeout = 60   # seconds before giving up on a batch download job

    def _children(self, hash):
        """ Get the SHA256 hashes of the files unpacked from the given sample, that is, the other files listed in the
             results of its analysis. """
        # the names of the search terms are only served by the API
        self._get("private/search/term")
        terms = [t.get('term') for t in getattr(self, "json", {}).get('search_terms') or [] if isinstance(t, dict)]
        if (term := next((t for t in ["sha256", "hash"] if t in terms), None)) is None:
            logger.debug(f"{self.name}: no search term for hashes among {terms}")
            return []
        self._post(f"private/search/term/{term}", json={'value': hash})
        # only keep analyses where the sample was the submitted file
        ids = [a['id'] for r in getattr(self, "json", {}).get('results') or [] if isinstance(r, dict)
               for a in r.get('analysis') or [] if isinstance(a, dict) and a.get('id') and
               str(a.get('submission_sha256', "")).lower() == hash]
        if len(ids) == 0:
            return []
        self._get(f"private/results/{ids[0]}")
        # results are a list of files including the parent, or a single MalwareID result (no unpacking)
        if not isinstance(results := getattr(self, "json", {}).get('results'), list):
            return []
        return list(dict.fromkeys(h for r in results if isinstance(r, dict) and
                                  (h := str((r.get('hashes') or {}).get('sha256', "")).lower()) and h != hash))

    def _fetch(self, hash):
        """ Download a file through a batch download job: request the job, wait for its link, then download the
             archive and extract the file. """
        import io
        import time
        import zipfile
        from requests import exceptions, get
        self._post("private/batch/download", json={'type': "hash", 'dlist': [hash]})
        if not (token := getattr(self, "json", {}).get('token')):
            raise HashNotFoundError(hash, self.__class__.__name__)
        for _ in range(max(1, int(self._poll_timeout / self._poll_interval))):
            try:
                # never answer from (nor store into) the requests cache while the job is in progress
                self._get(f"private/batch/download/{token}", headers={'Cache-Control': "no-store"})
                if isinstance(link := getattr(self, "json", {}).get('download_url'), str) and link.startswith("http"):
                    break
            except HashNotFoundError:
                pass  # the job is not ready yet
            time.sleep(self._poll_interval)
        else:
            raise ServiceUnavailable(self.__class__.__name__, "batch download job did not complete in time")
        try:
            # pre-signed link, hence no Authorization header
            r = get(link)
            r.raise_for_status()
        except exceptions.RequestException as e:
            raise ServiceUnavailable(self.__class__.__name__, e.__class__.__name__)
        self.content = r.content
        # the archive has no file if the sample is unknown ; it may be password-protected (user setting)
        try:
            with zipfile.ZipFile(io.BytesIO(self.content)) as z:
                if len(z.namelist()) == 0:
                    raise HashNotFoundError(hash, self.__class__.__name__)
            self._unzip(b"infected")
        except zipfile.BadZipFile:
            pass  # not an archive, hence the file itself
        return self

    def get_malware_feed(self):
        # latest page of the feed of unpacked samples (requires a plan with feed access)
        self._get("private/feed/unpacked")
        for submission in getattr(self, "json", {}).get('submissions') or []:
            if submission.get('submission_sha256'):
                yield submission['submission_sha256']

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        # an API key requires a paid plan and downloads are limited per month depending on the plan
        if getattr(self, "_unpacked", False):
            # unpacked files are saved under their own hashes ; any failure is not to prevent downloading the sample
            try:
                for child in self._children(hash):
                    try:
                        self._fetch(child)._save(child)
                    except (HashNotFoundError, ServiceUnavailable) as e:
                        logger.debug(e)
            except (HashNotFoundError, ServiceUnavailable) as e:
                logger.debug(e)
        self._fetch(hash)._save()
