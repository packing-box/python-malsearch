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

from malsearch import download_sample, AnyRun
from malsearch.clients.__common__ import API


API_KEY = "abcdef1234567890abcdef1234567890"
URL = "https://api.any.run/v1"
DATA = b"MZ fake sample"
HASHES = {'md5': hashlib.md5(DATA).hexdigest(), 'sha1': hashlib.sha1(DATA).hexdigest(),
          'sha256': hashlib.sha256(DATA).hexdigest()}
OTHER = {'md5': "0" * 32, 'sha1': "0" * 40, 'sha256': "0" * 64}
FILE_LINK = "https://content.any.run/tasks/72f52127/download/files/80577526"
MAIN_LINK = "https://content.any.run/tasks/1d84688a/download"
UUID = "1d84688a-876c-4d21-b5a3-bd9887c756c6"
AUTH = {'Authorization': f"API-Key {API_KEY}"}


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


def _zip(data):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        z.writestr("sample", data)
    return buffer.getvalue()


class TestAnyRun(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nanyrun = {API_KEY}\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _read(self, h):
        with open(os.path.join(self.tmp, h), 'rb') as f:
            return f.read()

    def test_download_related_file(self):
        for htype, h in HASHES.items():
            search = _json({'relatedFiles': [{'fileLink': "https://content.any.run/other", 'hashes': OTHER},
                                             {'fileLink': FILE_LINK, 'hashes': {k: v.upper() for k, v in HASHES.items()}}]})
            with mock.patch("requests.post", return_value=search) as post, \
                 mock.patch("requests.get", return_value=_response(DATA)) as get:
                AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
            post.assert_called_once_with(f"{URL}/intelligence/api/search", data=None, json={'query': h}, headers=AUTH)
            get.assert_called_once_with(FILE_LINK, headers=AUTH)
            self.assertEqual(self._read(h), DATA)

    def test_download_source_task(self):
        h = HASHES['sha256']
        search = _json({'relatedFiles': [], 'sourceTasks': [
            {'uuid': "other", 'mainObject': {'type': "url", 'hashes': OTHER}},
            {'uuid': UUID, 'mainObject': {'type': "file", 'hashes': HASHES}}]})
        report = _json({'error': False, 'data': {'analysis': {'content': {'mainObject': {
            'permanentUrl': MAIN_LINK, 'hashes': HASHES}}}}})
        with mock.patch("requests.post", return_value=search), \
             mock.patch("requests.get", side_effect=[report, _response(_zip(DATA))]) as get:
            AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        self.assertEqual(get.call_args_list, [mock.call(f"{URL}/analysis/{UUID}", params=None, headers=AUTH),
                                              mock.call(MAIN_LINK, headers=AUTH)])
        # the sample came zipped
        self.assertEqual(self._read(h), DATA)

    def test_download_apk(self):
        # an APK is a ZIP ; it must not be unzipped as it is the sample itself
        apk = _zip(b"classes.dex content")
        h = hashlib.sha256(apk).hexdigest()
        search = _json({'relatedFiles': [{'fileLink': FILE_LINK, 'hashes': {'sha256': h}}]})
        with mock.patch("requests.post", return_value=search), mock.patch("requests.get", return_value=_response(apk)):
            AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(h)
        self.assertEqual(self._read(h), apk)

    def test_foreign_link(self):
        # the API key must never be sent to another host than ANY.RUN's
        for link in ["https://evil.example.com/sample", "https://content.any.run.evil.com/x", "http://content.any.run/x"]:
            search = _json({'relatedFiles': [{'fileLink': link, 'hashes': HASHES}]})
            with mock.patch("requests.post", return_value=search), mock.patch("requests.get") as get:
                self.assertRaises(ServiceUnavailable, AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASHES['sha256'])
            get.assert_not_called()

    def test_hash_not_found(self):
        for search in [{}, {'relatedFiles': [{'fileLink': FILE_LINK, 'hashes': OTHER}],
                            'sourceTasks': [{'uuid': UUID, 'mainObject': {'hashes': OTHER}}]}]:
            with mock.patch("requests.post", return_value=_json(search)), mock.patch("requests.get") as get:
                self.assertRaises(HashNotFoundError, AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                                  HASHES['sha256'])
            get.assert_not_called()
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASHES['sha256'])))

    def test_private_content(self):
        search = _json({'relatedFiles': [{'fileLink': FILE_LINK, 'hashes': HASHES}]})
        with mock.patch("requests.post", return_value=search), \
             mock.patch("requests.get", return_value=_response(b"Private content", 403, "Forbidden")):
            self.assertRaises(ServiceUnavailable, AnyRun(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash,
                              HASHES['sha256'])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASHES['sha256'])))

    def test_unsupported_hash(self):
        with mock.patch("requests.post") as post:
            self.assertRaises(ValueError, AnyRun(api_key=API_KEY).get_file_by_hash, "a" * 128)
        post.assert_not_called()

    def test_invalid_key_or_license(self):
        for r, msg in [(_json({'statusCode': 401, 'message': "The provided authorization data is incorrect.",
                               'code': "WRONG_AUTH_DATA_ERROR"}, 401, "Unauthorized"),
                        "The provided authorization data is incorrect."),
                       (_json({'message': "Your license has expired. Please renew it from support@any.run.",
                               'code': "EXPIRED_LICENSE_ERROR"}, 402, "Payment Required"),
                        "Your license has expired.")]:
            API._disabled.clear()
            with open(self.conf, 'w') as f:
                f.write(f"[API keys]\nanyrun = {API_KEY}\n")
            with mock.patch("requests.post", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
                self.assertIsNone(download_sample(HASHES['sha256'], config=self.conf, output_dir=self.tmp))
            self.assertNotIn(API_KEY, "\n".join(logs.output))
            self.assertTrue(any("rejected the API key" in l and msg in l for l in logs.output))
            c = ConfigParser()
            c.read(self.conf)
            self.assertIn("anyrun", c['Disabled'])
