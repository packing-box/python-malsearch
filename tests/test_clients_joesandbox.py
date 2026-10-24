#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import io
import json
import os
import zipfile
from configparser import ConfigParser
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, JoeSandbox
from malsearch.clients.__common__ import API


API_KEY = "0" * 64
URL = "https://jbxcloud.joesecurity.org/api/v2"
DATA = b"MZ fake sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha1': hashlib.sha1(DATA).hexdigest(),
          'sha256': hashlib.sha256(DATA).hexdigest()}
SEARCH = {'data': [
    # matching on something else than the hash (e.g. a filename or a comment) must be ignored
    {'webid': "111", 'filename': HASHES['sha256'], 'md5': "0" * 32, 'sha1': "0" * 40, 'sha256': "0" * 64},
    {'webid': "222", 'filename': "sample.exe", **{k: v.upper() for k, v in HASHES.items()}},
]}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _zip(data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr("sample", data)
    return buffer.getvalue()


class TestJoeSandbox(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\njoesandbox = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _download(self, h, content):
        with mock.patch("requests.post", side_effect=[_response(json.dumps(SEARCH).encode()),
                                                      _response(content)]) as post:
            JoeSandbox(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        return post

    def test_download(self):
        for htype, h in HASHES.items():
            post = self._download(h, DATA)
            self.assertEqual(post.call_args_list, [
                mock.call(f"{URL}/analysis/search", data={'apikey': API_KEY, 'q': h}, json=None, headers=None),
                mock.call(f"{URL}/analysis/download", data={'apikey': API_KEY, 'webid': "222", 'type': "sample"},
                          json=None, headers=None),
            ])
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_download_zipped(self):
        self._download(HASHES['sha256'], _zip(DATA))
        with open(os.path.join(self.tmp, HASHES['sha256']), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_download_apk(self):
        # an APK is a ZIP ; it must not be unzipped as it is the sample itself
        apk = _zip(b"classes.dex content")
        h = hashlib.sha256(apk).hexdigest()
        search = {'data': [{'webid': "333", 'sha256': h}]}
        with mock.patch("requests.post", side_effect=[_response(json.dumps(search).encode()), _response(apk)]):
            JoeSandbox(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        with open(os.path.join(self.tmp, h), 'rb') as f:
            self.assertEqual(f.read(), apk)

    def test_hash_not_found(self):
        for search in [{'data': []}, {'data': SEARCH['data'][:1]}]:
            with mock.patch("requests.post", return_value=_response(json.dumps(search).encode())) as post:
                self.assertRaises(HashNotFoundError, JoeSandbox(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASHES['sha256'])
            post.assert_called_once()
            self.assertFalse(os.path.exists(os.path.join(self.tmp, HASHES['sha256'])))

    def test_unsupported_hash(self):
        with mock.patch("requests.post") as post:
            self.assertRaises(ValueError, JoeSandbox(api_key=API_KEY).get_file_by_hash, "a" * 128)
        post.assert_not_called()

    def test_invalid_key(self):
        r = _response(b'{"errors":[{"code":4,"message":"Invalid API key"}]}', 403, "Forbidden")
        with mock.patch("requests.post", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l and "Invalid API key" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("joesandbox", c['Disabled'])
