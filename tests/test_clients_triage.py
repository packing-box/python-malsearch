#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import json
import os
from configparser import ConfigParser
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, Triage
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef01234567"
URL = "https://tria.ge/api/v0"
DATA = b"MZ fake sample"
HASHES = {t: hashlib.new(t, DATA).hexdigest() for t in ["md5", "sha1", "sha256", "sha512"]}
HEADERS = {'Authorization': f"Bearer {API_KEY}"}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


class TestTriage(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\ntriage = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        for htype, h in HASHES.items():
            search = _json({'data': [{'id': "241025-abcdef", 'kind': "file"}]})
            with mock.patch("requests.get", side_effect=[search, _response(DATA)]) as get:
                Triage(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            self.assertEqual(get.call_args_list, [
                mock.call(f"{URL}/search", params={'query': f"{htype}:{h}"}, headers=HEADERS),
                mock.call(f"{URL}/samples/241025-abcdef/sample", params=None, headers=HEADERS)])
            with open(os.path.join(self.tmp, h), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        h = HASHES['sha256']
        with mock.patch("requests.get", return_value=_json({'data': []})) as get, \
             self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(h, config=self.conf, output_dir=self.tmp))
        get.assert_called_once()
        self.assertIn(f"WARNING:malsearch:could not find {h}", logs.output)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, Triage(api_key=API_KEY).get_file_by_hash, "a" * 56)
        get.assert_not_called()

    def test_invalid_key(self):
        r = _json({'error': "UNAUTHORIZED", 'message': "invalid token"}, 403, "Forbidden")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l and "invalid token" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("triage", c['Disabled'])
