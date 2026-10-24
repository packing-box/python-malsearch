#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import os
from configparser import ConfigParser
from datetime import datetime
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, PolySwarm
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef"
DATA = b"MZ fake sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha1': hashlib.sha1(DATA).hexdigest(),
          'sha256': hashlib.sha256(DATA).hexdigest()}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestPolySwarm(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\npolyswarm = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        for htype, h in HASHES.items():
            with mock.patch("requests.get", return_value=_response(DATA)) as get:
                PolySwarm(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            get.assert_called_once_with(f"https://api.polyswarm.network/v3/consumer/download/{htype}/{h}",
                                        params={'community': "default"}, headers={'Authorization': API_KEY})
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        for r in [_response(status=404, reason="NOT FOUND"), _response(status=204, reason="NO CONTENT")]:
            with mock.patch("requests.get", return_value=r):
                self.assertRaises(HashNotFoundError, PolySwarm(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASHES['sha256'])
            self.assertFalse(os.path.exists(os.path.join(self.tmp, HASHES['sha256'])))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, PolySwarm(api_key=API_KEY).get_file_by_hash, "a" * 128)
        get.assert_not_called()

    def test_rate_limit(self):
        for headers, seconds in [({'Retry-After': "3600"}, 3600), ({}, 300)]:
            API._disabled.clear()
            with open(self.conf, 'w') as f:
                f.write(f"[API keys]\npolyswarm = {API_KEY}\n")
            r = _response(b'{"errors":null,"result":"Too Many Requests","status":"error"}', 429, "TOO MANY REQUESTS")
            r.headers.update(headers)
            with mock.patch("requests.get", return_value=r) as get, self.assertLogs("malsearch", "DEBUG") as logs:
                for _ in range(3):
                    self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
                # a client created before the 429 (e.g. in another thread) must stop as well
                self.assertRaises(ServiceUnavailable, PolySwarm(api_key=API_KEY).get_file_by_hash, HASHES['md5'])
            get.assert_called_once()
            self.assertEqual(sum(l.startswith("WARNING") and "hit its rate limit" in l for l in logs.output), 1)
            self.assertFalse(any("is not known" in l for l in logs.output))
            c = ConfigParser()
            c.read(self.conf)
            until = datetime.strptime(c['Disabled']['polyswarm'], "%d/%m/%Y %H:%M:%S")
            self.assertAlmostEqual((until - datetime.now()).total_seconds(), seconds, delta=5)
    
    def test_invalid_key(self):
        for r in [_response(b'{"errors":null,"result":"Invalid API key","status":"error"}', 401, "UNAUTHORIZED"),
                  _response(b'{"errors":null,"result":"API Key must be a 32 character alphanumeric string",'
                            b'"status":"error"}', 400, "BAD REQUEST")]:
            API._disabled.clear()
            with open(self.conf, 'w') as f:
                f.write(f"[API keys]\npolyswarm = {API_KEY}\n")
            with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
                self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
            self.assertNotIn(API_KEY, "\n".join(logs.output))
            self.assertTrue(any("rejected the API key" in l for l in logs.output))
            self.assertFalse(any("is not known" in l for l in logs.output))
            c = ConfigParser()
            c.read(self.conf)
            self.assertIn("polyswarm", c['Disabled'])
