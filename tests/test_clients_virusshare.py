#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import io
import os
from pyzipper import AESZipFile, WZ_AES, ZIP_LZMA
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, VirusShare
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef"
URL = "https://virusshare.com/apiv2"
DATA = b"MZ fake sample"
HASHES = {t: hashlib.new(t, DATA).hexdigest() for t in ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _zip(data):
    with io.BytesIO() as buffer:
        with AESZipFile(buffer, 'w', compression=ZIP_LZMA, encryption=WZ_AES) as z:
            z.setpassword(b"infected")
            z.writestr("sample", data)
        return buffer.getvalue()


class TestVirusShare(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nvirusshare = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        # every hash type is supported and the sample comes zipped with password "infected"
        for h in HASHES.values():
            with mock.patch("requests.get", return_value=_response(_zip(DATA))) as get:
                VirusShare(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            get.assert_called_once_with(f"{URL}/download", params={'hash': h, 'apikey': API_KEY}, headers=None)
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        h = HASHES['sha256']
        with mock.patch("requests.get", return_value=_response(b"", 404, "Not Found")):
            self.assertRaises(HashNotFoundError, VirusShare(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_rate_limit(self):
        # a 429 disables the client for a while
        with mock.patch("requests.get", return_value=_response(b"", 429, "Too Many Requests")), \
             self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("hit its rate limit" in l for l in logs.output))
