# -*- coding: UTF-8 -*-
import threading

from .__common__ import _hash_type, hashtype, logger, API, HashNotFoundError, ServiceUnavailable


__all__ = ["TheZoo"]

_DEFAULT_PASSWORD = "infected"
_HASHES = ["md5", "sha1", "sha256"]
_TREE = "https://api.github.com/repos/ytisf/theZoo/git/trees/master"


def _cache_file():
    from os.path import join
    try:
        from platformdirs import user_cache_dir
        return join(user_cache_dir("malsearch"), "thezoo.json")
    except ImportError:
        from os.path import expanduser
        return join(expanduser("~/.cache/malsearch"), "thezoo.json")


def _members(content, password):
    """ Yield the files of an archive, encrypted (ZipCrypto or AES) or not. """
    import io
    import zipfile
    from pyzipper import AESZipFile
    # AESZipFile also reads regular archives
    with AESZipFile(io.BytesIO(content)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            for pwd in [None, password.encode()]:
                try:
                    yield info.filename, z.read(info, pwd=pwd)
                    break
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile):
                    continue


class TheZoo(API):
    doc = "https://github.com/ytisf/theZoo"
    url = "https://raw.githubusercontent.com/ytisf/theZoo/master"
    # public repository, hence no API key and no key to reject
    _requires_key = False
    _invalid_key = lambda s, r: False
    _index_lock = threading.Lock()
    _samples = None

    def _fetch(self, url, **kwargs):
        """ Thread-safe GET, as the index is built in parallel while _get stores its result in the instance. """
        from requests import exceptions, get
        try:
            r = get(url, **kwargs)
            r.raise_for_status()
        except exceptions.RequestException as e:
            raise ServiceUnavailable(self.__class__.__name__, e.__class__.__name__)
        return r

    def _index(self):
        """ Map the hashes of the samples to their archives. theZoo only publishes the hashes of its archives, hence
             the samples are hashed from the content of the archives listed in maldb.db, then cached locally per
             archive (keyed by its Git blob hash) so that only new or changed archives are downloaded again. """
        with TheZoo._index_lock:
            if TheZoo._samples is None:
                import json
                import os
                path = _cache_file()
                try:
                    with open(path) as f:
                        cache = json.load(f)
                except (OSError, ValueError):
                    cache = {}
                try:
                    archives = self._update(cache)
                except ServiceUnavailable as e:
                    if not cache:
                        raise
                    logger.warning(f"{self.name}: cannot update the index ({e}), hence using the cached one")
                    archives = cache
                else:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(f"{path}.tmp", 'w') as f:
                        json.dump(archives, f)
                    os.replace(f"{path}.tmp", path)
                TheZoo._samples = {h: (zip_path, a['password']) for zip_path, a in archives.items()
                                   for s in a['samples'] for h in s}
        return TheZoo._samples

    def _update(self, cache):
        import os
        import sqlite3
        import tempfile
        from contextlib import closing
        from concurrent.futures import ThreadPoolExecutor
        from urllib.parse import quote
        # maldb.db gives the locations of the samples, but the names of the files in each location vary
        with tempfile.TemporaryDirectory() as tmp:
            with open(db := os.path.join(tmp, "maldb.db"), 'wb') as f:
                f.write(self._fetch(f"{self.url}/conf/maldb.db").content)
            with closing(sqlite3.connect(db)) as conn:
                # source code archives (malware/Source) are left out as their files are not samples
                locations = {r[0].strip("/") for r in conn.execute("SELECT LOCATION FROM Malwares")
                             if r[0].strip("/").startswith("malware/Binaries/")}
        tree = self._fetch(_TREE, params={'recursive': 1}).json()['tree']
        files = {}
        for item in tree:
            if item['type'] == "blob" and (d := os.path.dirname(item['path'])) in locations:
                files.setdefault(d, []).append(item)
        archives, todo = {}, []
        for d, items in files.items():
            pwd = next((i['path'] for i in items if i['path'].endswith(".pass")), None)
            for i in items:
                if i['path'].endswith(".zip"):
                    if (a := cache.get(i['path'])) and a['sha'] == i['sha']:
                        archives[i['path']] = a
                    else:
                        todo.append((i, pwd))

        def _hash(task):
            import hashlib
            item, pwd = task
            try:
                password = self._fetch(f"{self.url}/{quote(pwd)}").text.strip() if pwd else _DEFAULT_PASSWORD
                # do not keep the archives in the requests cache (hundreds of MB)
                content = self._fetch(f"{self.url}/{quote(item['path'])}", headers={'Cache-Control': "no-store"}).content
            except ServiceUnavailable as e:
                # not cached, hence retried on the next run
                logger.debug(f"{self.name}: cannot index {item['path']} ({e})")
                return
            try:
                samples = [[hashlib.new(t, data).hexdigest() for t in _HASHES] for _, data in _members(content, password)]
            except Exception as e:
                # unreadable archive (e.g. a RAR named .zip), cached as empty until it changes
                logger.debug(f"{self.name}: cannot index {item['path']} ({e})")
                samples = []
            return item['path'], {'sha': item['sha'], 'password': password, 'samples': samples}

        if todo:
            logger.info(f"{self.name}: indexing {len(todo)} archive(s), this may take a while...")
            with ThreadPoolExecutor(max_workers=8) as executor:
                archives.update(r for r in executor.map(_hash, todo) if r is not None)
        return archives

    def get_malware_feed(self):
        yield from {h for h in self._index() if len(h) == 64}

    @hashtype(*_HASHES)
    def get_file_by_hash(self, hash):
        import hashlib
        from urllib.parse import quote
        if (entry := self._index().get(hash)) is None:
            raise HashNotFoundError(hash, self.__class__.__name__)
        zip_path, password = entry
        self._get(quote(zip_path))
        for _, data in _members(self.content, password):
            if hashlib.new(_hash_type(hash), data).hexdigest() == hash:
                self.content = data
                self._save()
                return
        # the archive changed since it was indexed
        raise HashNotFoundError(hash, self.__class__.__name__)
