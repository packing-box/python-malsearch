#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import json
import os
from configparser import ConfigParser
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, get_samples_feed, MalShare
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
URL = "https://malshare.com/api.php"
DATA = b"MZ fake sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha1': hashlib.sha1(DATA).hexdigest(),
          'sha256': hashlib.sha256(DATA).hexdigest()}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestMalShare(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nmalshare = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        for h in HASHES.values():
            with mock.patch("requests.get", return_value=_response(DATA)) as get:
                MalShare(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            get.assert_called_once_with(URL, params={'action': "getfile", 'hash': h, 'api_key': API_KEY}, headers=None)
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        h = HASHES['sha256']
        r = _response(f"Sample not found by hash ({h})".encode(), 404, "Not Found")
        with mock.patch("requests.get", return_value=r):
            self.assertRaises(HashNotFoundError, MalShare(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_invalid_key(self):
        r = _response(b"User specified in `api_key` GET variable does not exist", 400, "Bad Request")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("malshare", c['Disabled'])

    def test_feed(self):
        samples = [{'md5': "0" * 32, 'sha1': "0" * 40, 'sha256': hashlib.sha256(str(i).encode()).hexdigest().upper()}
                   for i in range(3)]
        with mock.patch("requests.get", return_value=_response(json.dumps(samples + [{'md5': "1" * 32}]).encode())) \
             as get:
            feed = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with(URL, params={'action': "getlist", 'api_key': API_KEY}, headers=None)
        self.assertEqual(feed, [s['sha256'].lower() for s in samples])
