#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import os
import threading
import time
from configparser import ConfigParser
from requests import exceptions, Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, AndroZoo


API_KEY = "s3cr3t-k3y"
DATA = b"PK fake apk"
HASH = hashlib.sha256(DATA).hexdigest()


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestAndroZoo(TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        with mock.patch("requests.get", return_value=_response(DATA)) as get:
            AndroZoo(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        get.assert_called_once_with("https://androzoo.uni.lu/api/download", params={'sha256': HASH, 'apikey': API_KEY},
                                    headers=None)
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        with mock.patch("requests.get", return_value=_response(status=404, reason="NOT FOUND")):
            self.assertRaises(HashNotFoundError, AndroZoo(api_key=API_KEY).get_file_by_hash, HASH)

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, AndroZoo(api_key=API_KEY).get_file_by_hash, HASH[:32])
        get.assert_not_called()

    def test_invalid_key(self):
        conf = os.path.join(self.tmp, "malsearch.conf")
        with open(conf, 'w') as f:
            f.write(f"[API keys]\nandrozoo = {API_KEY}\n")
        r = _response(b'{"error":"Invalid apikey"}', 400, "BAD REQUEST")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))
        c = ConfigParser()
        c.read(conf)
        self.assertIn("androzoo", c['Disabled'])

    def test_missing_key(self):
        conf = os.path.join(self.tmp, "malsearch.conf")
        with open(conf, 'w') as f:
            f.write("[API keys]\nmalshare = some-key\n")
        with mock.patch("requests.get") as get, self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=conf, output_dir=self.tmp, select=["androzoo"]))
            self.assertIsNone(download_sample(HASH, config=conf, output_dir=self.tmp, select=["androzoo"]))
        get.assert_not_called()
        warning = "Did you forget to set up the API key for client 'androzoo' ?"
        self.assertEqual(sum(warning in l for l in logs.output), 1)
    
    def test_other_client_error(self):
        r = _response(b'{"error":"something else"}', 400, "BAD REQUEST")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            AndroZoo(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertFalse(any("rejected the API key" in l for l in logs.output))

    def test_connection_error(self):
        err = exceptions.ConnectionError(f"Max retries exceeded with url: /api/download?apikey={API_KEY}")
        with mock.patch("requests.get", side_effect=err):
            with self.assertRaises(ServiceUnavailable) as ctx:
                AndroZoo(api_key=API_KEY).get_file_by_hash(HASH)
        self.assertNotIn(API_KEY, str(ctx.exception))

    def test_concurrency_cap(self):
        lock, state = threading.Lock(), {'active': 0, 'peak': 0}
        def _slow_get(*args, **kwargs):
            with lock:
                state['active'] += 1
                state['peak'] = max(state['peak'], state['active'])
            time.sleep(.05)
            with lock:
                state['active'] -= 1
            return _response(DATA)
        with mock.patch("requests.get", side_effect=_slow_get), self.assertLogs("malsearch", "WARNING"):
            threads = [threading.Thread(target=AndroZoo(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                        args=(hashlib.sha256(str(i).encode()).hexdigest(), )) for i in range(40)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(state['peak'], 20)
