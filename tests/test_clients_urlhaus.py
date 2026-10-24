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

from malsearch import download_sample, get_samples_feed, URLhaus
from malsearch.clients.__common__ import API


API_KEY = "s3cr3t-k3y"
DATA = b"MZ fake payload"
HASH = hashlib.sha256(DATA).hexdigest()


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _zip(data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr(HASH, data)
    return buffer.getvalue()


class TestURLhaus(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nurlhaus = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        with mock.patch("requests.get", return_value=_response(_zip(DATA))) as get:
            URLhaus(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        get.assert_called_once_with(f"https://urlhaus-api.abuse.ch/v1/download/{HASH}/", params=None,
                                    headers={'Auth-Key': API_KEY})
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        for r in [_response(b'{"query_status": "not_found"}'), _response(b"not_found"),
                  _response(b'{"query_status": "copy_error"}'), _response(status=404, reason="NOT FOUND")]:
            with mock.patch("requests.get", return_value=r):
                self.assertRaises(HashNotFoundError, URLhaus(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASH)
            self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, URLhaus(api_key=API_KEY).get_file_by_hash, HASH[:32])
        get.assert_not_called()

    def test_invalid_key(self):
        r = _response(b'{\n    "query_status": "unknown_auth_key"\n}', 403, "FORBIDDEN")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("urlhaus", c['Disabled'])

    def test_feed(self):
        payloads = [{'md5_hash': hashlib.md5(str(i).encode()).hexdigest(),
                     'sha256_hash': hashlib.sha256(str(i).encode()).hexdigest()} for i in range(3)]
        r = _response(json.dumps({'query_status': "ok", 'payloads': payloads}).encode())
        with mock.patch("requests.get", return_value=r) as get:
            hashes = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with("https://urlhaus-api.abuse.ch/v1/payloads/recent/limit/1000/", params=None,
                                    headers={'Auth-Key': API_KEY})
        self.assertEqual(hashes, [p['sha256_hash'] for p in payloads])
        with mock.patch("requests.get", return_value=_response(b'{"query_status": "no_results"}')):
            self.assertEqual(list(get_samples_feed(config=self.conf)), [])
