#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import json
import os
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, get_samples_feed, Maldatabase
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef"
URL = "https://api.maldatabase.com/download"
SAMPLES = [{t: hashlib.new(t, str(i).encode()).hexdigest() for t in ["md5", "sha1", "sha256"]} for i in range(3)]


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestMaldatabase(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nmaldatabase = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_feed(self):
        with mock.patch("requests.get", return_value=_response(json.dumps(SAMPLES).encode())) as get:
            feed = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with(f"{URL}/", params=None,
                                    headers={'Accept-Encoding': "gzip, deflate", 'Authorization': API_KEY})
        self.assertEqual(feed, [s['sha256'] for s in SAMPLES])
        # other hash types
        with mock.patch("requests.get", return_value=_response(json.dumps(SAMPLES).encode())):
            self.assertEqual(list(Maldatabase(api_key=API_KEY).get_malware_feed("md5")), [s['md5'] for s in SAMPLES])

    def test_feed_unavailable(self):
        with mock.patch("requests.get", return_value=_response(b"", 503, "Service Unavailable")), \
             self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertEqual(list(get_samples_feed(config=self.conf)), [])
        self.assertTrue(any("currently unavailable (503 - Service Unavailable)" in l for l in logs.output))

    def test_no_download(self):
        # feed only: not used for downloading
        with mock.patch("requests.get") as get, self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(SAMPLES[0]['sha256'], config=self.conf, output_dir=self.tmp))
        get.assert_not_called()
        self.assertTrue(any("no download client available" in l for l in logs.output))
