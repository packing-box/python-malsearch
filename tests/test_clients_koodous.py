#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import json
import os
from configparser import ConfigParser
from datetime import datetime
from requests import exceptions, Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, Koodous
from malsearch.clients.__common__ import API


API_KEY = "c080ddd1fab46bc919ca0d62299e9995b1886853"
DATA = b"PK fake apk"
HASH = hashlib.sha256(DATA).hexdigest()
LINK = f"https://storage.example.com/{HASH}?X-Amz-Signature=abc"


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestKoodous(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nkoodous = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        for field in ["download_url", "url", "link", "download_link"]:
            with mock.patch("requests.get", side_effect=[_response(json.dumps({field: LINK}).encode()),
                                                         _response(DATA)]) as get:
                Koodous(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
            self.assertEqual(get.call_args_list, [
                mock.call(f"https://developer.koodous.com/apks/{HASH}/download/", params=None,
                          headers={'Authorization': f"Token {API_KEY}"}),
                mock.call(LINK),  # no token sent to the storage
            ])
            with open(os.path.join(self.tmp, HASH), 'rb') as f:
                self.assertEqual(f.read(), DATA)
            os.remove(os.path.join(self.tmp, HASH))

    def test_hash_not_found(self):
        for r in [_response(b'{"detail":"Not found."}', 404, "Not Found"), _response(b'{"something": "else"}')]:
            with mock.patch("requests.get", return_value=r) as get:
                self.assertRaises(HashNotFoundError, Koodous(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASH)
            get.assert_called_once()
            self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_expired_link(self):
        with mock.patch("requests.get", side_effect=[_response(json.dumps({'download_url': LINK}).encode()),
                                                     _response(b"<Error>AccessDenied</Error>", 403, "Forbidden")]):
            self.assertRaises(ServiceUnavailable, Koodous(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))
        # a storage error must not be taken for a rejected key
        self.assertNotIn("koodous", API._disabled)

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, Koodous(api_key=API_KEY).get_file_by_hash, HASH[:32])
        get.assert_not_called()

    def test_invalid_key(self):
        r = _response(b'{"detail":"Invalid token."}', 401, "Unauthorized")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l and "Invalid token." in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("koodous", c['Disabled'])

    def test_quota(self):
        r = _response(b'{"detail":"Request was throttled. Expected available in 86400 seconds."}', 429,
                      "Too Many Requests")
        r.headers['Retry-After'] = "86400"
        with mock.patch("requests.get", return_value=r) as get, self.assertLogs("malsearch", "DEBUG") as logs:
            for _ in range(2):
                self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
        get.assert_called_once()
        self.assertTrue(any("hit its rate limit or quota" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        until = datetime.strptime(c['Disabled']['koodous'], "%d/%m/%Y %H:%M:%S")
        self.assertAlmostEqual((until - datetime.now()).total_seconds(), 86400, delta=5)
