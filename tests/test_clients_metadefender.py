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

from malsearch import download_sample, get_samples_feed, MetaDefender
from malsearch.clients.__common__ import API


API_KEY = "0123456789abcdef0123456789abcdef"
URL = "https://api.metadefender.com/v4"
DATA = b"MZ fake sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha1': hashlib.sha1(DATA).hexdigest(),
          'sha256': hashlib.sha256(DATA).hexdigest()}
LINK = "https://mdcloud-samples.s3.amazonaws.com/abc?X-Amz-Signature=def"


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


def _zip(*files, password=None):
    buffer = io.BytesIO()
    if password:
        from pyzipper import AESZipFile, WZ_AES, ZIP_LZMA
        with AESZipFile(buffer, 'w', compression=ZIP_LZMA, encryption=WZ_AES) as z:
            z.setpassword(password)
            for name, data in files:
                z.writestr(name, data)
    else:
        with zipfile.ZipFile(buffer, 'w') as z:
            for name, data in files:
                z.writestr(name, data)
    return buffer.getvalue()


class TestMetaDefender(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nmetadefender = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _read(self, h):
        with open(os.path.join(self.tmp, h), 'rb') as f:
            return f.read()

    def test_download(self):
        for h in HASHES.values():
            with mock.patch("requests.get", side_effect=[_json({'url': LINK}), _response(DATA)]) as get:
                MetaDefender(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            # the key is sent to the API but not with the pre-signed link
            self.assertEqual(get.call_args_list, [mock.call(f"{URL}/file/{h}/download", params=None,
                                                            headers={'apikey': API_KEY}), mock.call(LINK)])
            self.assertEqual(self._read(h), DATA)

    def test_download_from_archive(self):
        # the sample is in an archive (possibly protected with "infected"), among other files
        h = HASHES['sha256']
        for archive in [_zip(("readme.txt", b"other"), ("sample.exe", DATA)),
                        _zip(("sample.exe", DATA), password=b"infected")]:
            with mock.patch("requests.get", side_effect=[_json({'url': LINK}), _response(archive)]):
                MetaDefender(api_key=API_KEY, output_dir=self.tmp, overwrite=True).get_file_by_hash(h)
            self.assertEqual(self._read(h), DATA)

    def test_download_apk(self):
        # an APK is a ZIP ; it must not be extracted as it is the sample itself
        apk = _zip(("classes.dex", b"content"))
        h = hashlib.sha256(apk).hexdigest()
        with mock.patch("requests.get", side_effect=[_json({'url': LINK}), _response(apk)]):
            MetaDefender(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        self.assertEqual(self._read(h), apk)

    def test_hash_not_found(self):
        h = HASHES['sha256']
        for r in [_json({'error': {'code': 404003, 'messages': ["The hash was not found"]}}, 404, "Not Found"),
                  _json({})]:
            with mock.patch("requests.get", return_value=r) as get:
                self.assertRaises(HashNotFoundError, MetaDefender(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  h)
            get.assert_called_once()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_link_failure(self):
        h = HASHES['sha256']
        with mock.patch("requests.get", side_effect=[_json({'url': LINK}), _response(b"", 403, "Forbidden")]):
            self.assertRaises(ServiceUnavailable, MetaDefender(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                              h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, MetaDefender(api_key=API_KEY).get_file_by_hash, "a" * 128)
        get.assert_not_called()

    def test_invalid_key(self):
        r = _json({'error': {'code': 401000, 'messages': ["Unauthorized"]}}, 401, "Unauthorized")
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l and "server said: Unauthorized" in l for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("metadefender", c['Disabled'])

    def test_feed(self):
        hashes = [{'md5': "0" * 32, 'sha1': "0" * 40, 'sha256': hashlib.sha256(str(i).encode()).hexdigest().upper(),
                   'total_detected_avs': 10} for i in range(3)]
        data = {'from': "2026-09-25", 'to': "2026-10-25", 'length': 3, 'hashes': hashes + [{'md5': "1" * 32}]}
        with mock.patch("requests.get", return_value=_json(data)) as get:
            feed = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with(f"{URL}/feed/infected/latest", params=None, headers={'apikey': API_KEY})
        self.assertEqual(feed, [h['sha256'].lower() for h in hashes])
