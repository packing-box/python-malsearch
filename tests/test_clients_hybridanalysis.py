#!/usr/bin/python
# -*- coding: UTF-8 -*-
import gzip
import hashlib
import json
import os
from configparser import ConfigParser
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, get_samples_feed, HybridAnalysis
from malsearch.clients.__common__ import API


API_KEY = "0" * 64
DATA = b"MZ fake sample"
HASH = hashlib.sha256(DATA).hexdigest()


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestHybridAnalysis(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nhybridanalysis = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        with mock.patch("requests.get", return_value=_response(gzip.compress(DATA))) as get:
            HybridAnalysis(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        get.assert_called_once_with(f"https://hybrid-analysis.com/api/v2/overview/{HASH}/sample", params=None,
                                    headers={'api-key': API_KEY})
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        r = _response(b'{"message":"Requested URI - Not Found"}', 404, "Not Found")
        with mock.patch("requests.get", return_value=r):
            self.assertRaises(HashNotFoundError, HybridAnalysis(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                              HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, HybridAnalysis(api_key=API_KEY).get_file_by_hash, HASH[:32])
        get.assert_not_called()

    def test_invalid_key(self):
        msg = "Invalid API key. Please verify your credentials and try again."
        r = _response(json.dumps({'message': msg}).encode(), 403, "Forbidden")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        # the server's message is shown so that e.g. a missing download permission is not mistaken for a bad key
        self.assertTrue(any("rejected the API key" in l and msg in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("hybridanalysis", c['Disabled'])

    def test_feed(self):
        reports = [{'job_id': str(i), 'sha256': hashlib.sha256(str(i).encode()).hexdigest()} for i in range(3)]
        r = _response(json.dumps({'count': 4, 'status': "ok", 'data': reports + [{'job_id': "3"}]}).encode())
        with mock.patch("requests.get", return_value=r) as get:
            hashes = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with("https://hybrid-analysis.com/api/v2/feed/latest", params=None,
                                    headers={'api-key': API_KEY})
        self.assertEqual(hashes, [r['sha256'] for r in reports])
