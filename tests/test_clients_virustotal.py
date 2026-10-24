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

from malsearch import download_sample, VirusTotal
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
URL = "https://www.virustotal.com/api/v3"
DATA = b"MZ fake packed sample"
UNPACKED = b"MZ fake unpacked sample"
HASH = hashlib.sha256(DATA).hexdigest()
HASH2 = hashlib.sha256(UNPACKED).hexdigest()
HEADERS = {'x-apikey': API_KEY}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


class TestVirusTotal(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nvirustotal = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _read(self, h):
        with open(os.path.join(self.tmp, h), 'rb') as f:
            return f.read()

    def test_download(self):
        for h in [hashlib.md5(DATA).hexdigest(), hashlib.sha1(DATA).hexdigest(), HASH]:
            with mock.patch("requests.get", return_value=_response(DATA)) as get, \
                 self.assertNoLogs("malsearch", "WARNING"):
                VirusTotal(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            get.assert_called_once_with(f"{URL}/files/{h}/download", params=None, headers=HEADERS)
            self.assertEqual(self._read(h), DATA)

    def test_download_zipped(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            z.writestr(HASH, DATA)
        with mock.patch("requests.get", return_value=_response(buffer.getvalue())):
            VirusTotal(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        self.assertEqual(self._read(HASH), DATA)

    def test_download_unpacked(self):
        report = _json({'data': {'attributes': {'names': ["sample.exe", f"{HASH2}_unpacked"]}}})
        with mock.patch("requests.get", side_effect=[report, _response(UNPACKED), _response(DATA)]) as get:
            VirusTotal(api_key=API_KEY, output_dir=self.tmp, unpacked=True).get_file_by_hash(HASH)
        self.assertEqual([c.args[0] for c in get.call_args_list],
                         [f"{URL}/files/{HASH}", f"{URL}/files/{HASH2}/download", f"{URL}/files/{HASH}/download"])
        self.assertEqual(self._read(HASH2), UNPACKED)
        self.assertEqual(self._read(HASH), DATA)

    def test_hash_not_found(self):
        r = _json({'error': {'code': "NotFoundError", 'message': f"File \"{HASH}\" not found"}}, 404, "Not Found")
        with mock.patch("requests.get", return_value=r):
            self.assertRaises(HashNotFoundError, VirusTotal(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                              HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, VirusTotal(api_key=API_KEY).get_file_by_hash, "a" * 128)
        get.assert_not_called()

    def test_invalid_key(self):
        for r, msg in [(_json({'error': {'code': "WrongCredentialsError", 'message': "Wrong API key"}}, 401,
                              "Unauthorized"), "Wrong API key"),
                       (_json({'error': {'code': "ForbiddenError", 'message': "You are not allowed to perform the "
                              "requested operation"}}, 403, "Forbidden"), "You are not allowed")]:
            API._disabled.clear()
            with open(self.conf, 'w') as f:
                f.write(f"[API keys]\nvirustotal = {API_KEY}\n")
            with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
                self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
            self.assertNotIn(API_KEY, "\n".join(logs.output))
            self.assertTrue(any("rejected the API key" in l and msg in l for l in logs.output))
            c = ConfigParser()
            c.read(self.conf)
            self.assertIn("virustotal", c['Disabled'])
