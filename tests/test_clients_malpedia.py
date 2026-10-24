#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import io
import json
import os
from pyzipper import AESZipFile, WZ_AES, ZIP_LZMA
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import Malpedia
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef01234567"
URL = "https://malpedia.caad.fkie.fraunhofer.de/api"
DATA = b"MZ fake packed sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha256': hashlib.sha256(DATA).hexdigest()}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _zip(*files):
    with io.BytesIO() as buffer:
        with AESZipFile(buffer, 'w', compression=ZIP_LZMA, encryption=WZ_AES) as z:
            z.setpassword(b"infected")
            for name, data in files:
                z.writestr(name, data)
        return buffer.getvalue()


class TestMalpedia(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        # the archive holds the unpacked or dumped files too, possibly listed first
        archive = _zip(("win.foo/2024/sample_unpacked", b"MZ unpacked"), ("win.foo/2024/sample", DATA),
                       ("win.foo/2024/sample_dump_0x400000", b"MZ dump"))
        for h in HASHES.values():
            with mock.patch("requests.get", return_value=_response(archive)) as get, \
                 self.assertNoLogs("malsearch", "WARNING"):
                Malpedia(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            get.assert_called_once_with(f"{URL}/get/sample/{h}/zip", params=None,
                                        headers={'Authorization': f"APIToken {API_KEY}"})
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_sample_not_in_archive(self):
        # the archive is saved as is, with a warning, if no file matches the hash
        h = HASHES['sha256']
        archive = _zip(("other", b"MZ other"))
        with mock.patch("requests.get", return_value=_response(archive)), \
             self.assertLogs("malsearch", "WARNING") as logs:
            Malpedia(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        self.assertTrue(any("mismatch" in l for l in logs.output))
        with open(os.path.join(self.tmp, h), 'rb') as f:
            self.assertEqual(f.read(), archive)

    def test_hash_not_found(self):
        h = HASHES['sha256']
        r = _response(json.dumps({'detail': "Not found."}).encode(), 404, "Not Found")
        with mock.patch("requests.get", return_value=r):
            self.assertRaises(HashNotFoundError, Malpedia(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, Malpedia(api_key=API_KEY).get_file_by_hash, "a" * 40)
        get.assert_not_called()
