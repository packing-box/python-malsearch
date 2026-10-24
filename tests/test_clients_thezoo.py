#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import io
import json
import os
import sqlite3
import sys
from pyzipper import AESZipFile, WZ_AES, ZIP_DEFLATED
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, get_samples_feed, TheZoo
from malsearch.clients import thezoo
from malsearch.clients.__common__ import API


RAW = "https://raw.githubusercontent.com/ytisf/theZoo/master"
SAMPLES = {"Win32.Foo": {"foo.exe": b"MZ foo", "foo.dll": b"MZ foo dll"}, "Linux.Bar": {"bar.elf": b"\x7fELF bar"}}


def _zip(files, password):
    with io.BytesIO() as buffer:
        with AESZipFile(buffer, 'w', compression=ZIP_DEFLATED, encryption=WZ_AES) as z:
            z.setpassword(password.encode())
            for name, data in files.items():
                z.writestr(name, data)
        return buffer.getvalue()


def _db(locations):
    with TemporaryDirectory() as tmp:
        with sqlite3.connect(p := os.path.join(tmp, "maldb.db")) as conn:
            conn.execute("CREATE TABLE Malwares (ID INTEGER PRIMARY KEY, LOCATION TEXT NOT NULL)")
            conn.executemany("INSERT INTO Malwares (LOCATION) VALUES (?)", [(l, ) for l in locations])
        conn.close()
        with open(p, 'rb') as f:
            return f.read()


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class FakeRepo:
    """ theZoo's layout: one folder per sample in maldb.db, with an encrypted archive, its password and the hashes of
         the archive (not of the samples), the file names not always matching the folder name. """
    def __init__(self, samples=SAMPLES):
        self.files = {"conf/maldb.db": _db([f"malware/Binaries/{d}" for d in samples] + ["malware/Source/Original/X"])}
        for d, files in samples.items():
            name = d.lower()
            self.files[f"malware/Binaries/{d}/{name}.zip"] = _zip(files, pwd := f"pass-{name}")
            self.files[f"malware/Binaries/{d}/{name}.pass"] = pwd.encode() + b"\n"
            self.files[f"malware/Binaries/{d}/{name}.md5"] = b"0" * 32
        self.shas, self.calls = {p: "1" for p in self.files}, []

    def get(self, url, params=None, headers=None, **kwargs):
        self.calls.append(url)
        if url == thezoo._TREE:
            tree = [{'path': p, 'type': "blob", 'sha': self.shas[p]} for p in self.files]
            return _response(json.dumps({'tree': tree + [{'path': "malware", 'type': "tree", 'sha': "x"}]}).encode())
        p = url.removeprefix(f"{RAW}/").replace("%20", " ")
        if p in self.files:
            return _response(self.files[p])
        return _response(b"404: Not Found", 404, "Not Found")


class TestTheZoo(TestCase):
    def setUp(self):
        API._disabled.clear()
        TheZoo._samples = None
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.cache = os.path.join(self.tmp, "cache", "thezoo.json")
        self._patch = mock.patch.object(thezoo, "_cache_file", return_value=self.cache)
        self._patch.start()
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        # no API key, the client only needs to be listed
        with open(self.conf, 'w') as f:
            f.write("[API keys]\nthezoo =\n")

    def tearDown(self):
        self._patch.stop()
        TheZoo._samples = None
        self._tmp.cleanup()

    def _read(self, h):
        with open(os.path.join(self.tmp, h), 'rb') as f:
            return f.read()

    def test_download(self):
        repo = FakeRepo()
        with mock.patch("requests.get", side_effect=repo.get):
            for files in SAMPLES.values():
                for data in files.values():
                    for t in ["md5", "sha1", "sha256"]:
                        h = hashlib.new(t, data).hexdigest()
                        TheZoo(output_dir=self.tmp).get_file_by_hash(h)
                        self.assertEqual(self._read(h), data)
        # the index is built once
        self.assertEqual(repo.calls.count(thezoo._TREE), 1)

    def test_download_from_config(self):
        data = SAMPLES['Linux.Bar']['bar.elf']
        h = hashlib.sha256(data).hexdigest()
        with mock.patch("requests.get", side_effect=FakeRepo().get):
            self.assertIsNotNone(download_sample(h, config=self.conf, output_dir=self.tmp))
        self.assertEqual(self._read(h), data)

    def test_feed(self):
        with mock.patch("requests.get", side_effect=FakeRepo().get):
            feed = set(get_samples_feed(config=self.conf))
        self.assertEqual(feed, {hashlib.sha256(d).hexdigest() for fs in SAMPLES.values() for d in fs.values()})

    def test_hash_not_found(self):
        with mock.patch("requests.get", side_effect=FakeRepo().get):
            for h in ["0" * 64, hashlib.md5(FakeRepo().files["malware/Binaries/Win32.Foo/win32.foo.zip"]).hexdigest()]:
                # the hash of an archive is not the hash of a sample
                self.assertRaises(HashNotFoundError, TheZoo(output_dir=self.tmp).get_file_by_hash, h)
                self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_incremental_index(self):
        repo = FakeRepo()
        with mock.patch("requests.get", side_effect=repo.get):
            TheZoo()._index()
        self.assertTrue(os.path.exists(self.cache))
        # next run: unchanged archives are not downloaded again
        TheZoo._samples, repo.calls = None, []
        with mock.patch("requests.get", side_effect=repo.get):
            TheZoo()._index()
        self.assertFalse(any(u.endswith(".zip") for u in repo.calls))
        # a changed archive is downloaded again
        TheZoo._samples, repo.calls = None, []
        z = "malware/Binaries/Win32.Foo/win32.foo.zip"
        repo.files[z], repo.shas[z] = _zip({"foo.exe": b"MZ foo v2"}, "pass-win32.foo"), "2"
        with mock.patch("requests.get", side_effect=repo.get):
            idx = TheZoo()._index()
        self.assertEqual([u for u in repo.calls if u.endswith(".zip")], [f"{RAW}/{z}"])
        self.assertIn(hashlib.sha256(b"MZ foo v2").hexdigest(), idx)
        self.assertNotIn(hashlib.sha256(b"MZ foo").hexdigest(), idx)

    def test_archives_not_cached_by_requests_cache(self):
        repo = FakeRepo()
        with mock.patch("requests.get", side_effect=repo.get) as get:
            TheZoo()._index()
        for call in get.call_args_list:
            if call.args[0].endswith(".zip"):
                self.assertEqual(call.kwargs['headers'], {'Cache-Control': "no-store"})

    def test_failed_archive_retried(self):
        repo = FakeRepo()
        broken = repo.get
        with mock.patch("requests.get", side_effect=lambda u, **kw: _response(b"", 500, "Server Error")
                        if u.endswith("linux.bar.zip") else broken(u, **kw)):
            idx = TheZoo()._index()
        self.assertNotIn(hashlib.sha256(SAMPLES['Linux.Bar']['bar.elf']).hexdigest(), idx)
        TheZoo._samples = None
        with mock.patch("requests.get", side_effect=repo.get):
            idx = TheZoo()._index()
        self.assertIn(hashlib.sha256(SAMPLES['Linux.Bar']['bar.elf']).hexdigest(), idx)

    def test_unreadable_archive(self):
        repo = FakeRepo()
        repo.files["malware/Binaries/Linux.Bar/linux.bar.zip"] = b"Rar!\x1a\x07\x00 not a zip"
        with mock.patch("requests.get", side_effect=repo.get):
            idx = TheZoo()._index()
        self.assertIn(hashlib.sha256(SAMPLES['Win32.Foo']['foo.exe']).hexdigest(), idx)
        # not downloaded again as long as it does not change
        TheZoo._samples, repo.calls = None, []
        with mock.patch("requests.get", side_effect=repo.get):
            TheZoo()._index()
        self.assertFalse(any(u.endswith(".zip") for u in repo.calls))

    def test_github_unavailable(self):
        down = lambda u, **kw: _response(b"", 503, "Service Unavailable")
        # no cached index yet
        with mock.patch("requests.get", side_effect=down):
            self.assertRaises(ServiceUnavailable, TheZoo().get_file_by_hash, "0" * 64)
        # cached index used as a fallback
        with mock.patch("requests.get", side_effect=FakeRepo().get):
            TheZoo()._index()
        TheZoo._samples = None
        with mock.patch("requests.get", side_effect=down), self.assertLogs("malsearch", "WARNING"):
            idx = TheZoo()._index()
        self.assertIn(hashlib.sha256(SAMPLES['Linux.Bar']['bar.elf']).hexdigest(), idx)

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, TheZoo().get_file_by_hash, "0" * 128)
        get.assert_not_called()

    def test_archive_changed(self):
        # the archive changed since it was indexed: the sample is not in it anymore
        repo = FakeRepo()
        h = hashlib.sha256(SAMPLES['Linux.Bar']['bar.elf']).hexdigest()
        with mock.patch("requests.get", side_effect=repo.get):
            TheZoo()._index()
            repo.files["malware/Binaries/Linux.Bar/linux.bar.zip"] = _zip({"bar.elf": b"other"}, "pass-linux.bar")
            self.assertRaises(HashNotFoundError, TheZoo(output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_members(self):
        # folders are skipped, as well as corrupted files, while the other files are still read
        with io.BytesIO() as buffer:
            with AESZipFile(buffer, 'w', compression=ZIP_DEFLATED, encryption=WZ_AES) as z:
                z.setpassword(b"pwd")
                z.writestr("folder/", b"")
                z.writestr("folder/broken", b"MZ broken")
                z.writestr("folder/sample", b"MZ sample")
            content = bytearray(buffer.getvalue())
        # corrupt the encrypted data of the first file (its authentication code then mismatches)
        i = content.index(b"folder/broken") + len(b"folder/broken") + 11 + 20
        content[i] ^= 0xff
        self.assertEqual(list(thezoo._members(bytes(content), "pwd")), [("folder/sample", b"MZ sample")])


class TestCacheFile(TestCase):
    def test_cache_file(self):
        with mock.patch.dict(sys.modules, {'platformdirs': mock.Mock(user_cache_dir=lambda n: f"/cache/{n}")}):
            self.assertEqual(thezoo._cache_file(), "/cache/malsearch/thezoo.json")
        with mock.patch.dict(sys.modules, {'platformdirs': None}):
            self.assertEqual(thezoo._cache_file(), os.path.expanduser("~/.cache/malsearch/thezoo.json"))
