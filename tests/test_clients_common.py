#!/usr/bin/python
# -*- coding: UTF-8 -*-
import datetime as dt
import hashlib
import io
import json
import os
import sys
import types
import zipfile
from configparser import ConfigParser
from requests import exceptions, Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch.clients.__common__ import _hash_type, _server_message, _valid_hash, hashtype, _Base, API, Web


TEST_HASHES = {
    'md5':    "098f6bcd4621d373cade4e832627b4f6",
    'sha1':   "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    'sha224': "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
    'sha256': "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    'sha384': "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
    'sha512': "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
}
API_KEY = "s3cr3t-k3y"
DATA = b"MZ fake sample"
HASH = hashlib.sha256(DATA).hexdigest()


class DummyClient(_Base):
    pass


class DummyAPI(API):
    url = "https://api.example.com"
    _api_key_header = "X-Key"
    _headers = {'Accept': "application/json"}

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        self._get(f"files/{hash}")._save()


def _response(content=b"", status=200, reason="OK", headers=None):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    r.headers.update(headers or {})
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


def _zip(*files, password=None):
    from pyzipper import AESZipFile, WZ_AES
    buffer = io.BytesIO()
    if password:
        with AESZipFile(buffer, 'w', encryption=WZ_AES) as z:
            z.setpassword(password)
            for name, data in files:
                z.writestr(name, data)
    else:
        with zipfile.ZipFile(buffer, 'w') as z:
            for name, data in files:
                z.writestr(name, data)
    return buffer.getvalue()


class TestHashes(TestCase):
    def test_hash_functions(self):
        @hashtype("sha1", "sha256")
        def test_func(hash):
            pass
        self.assertRaises(ValueError, _valid_hash, "bad")
        for htype, h in TEST_HASHES.items():
            self.assertEqual(_valid_hash(h), h.lower())
            self.assertEqual(_valid_hash(h.upper()), h)
            self.assertEqual(_hash_type(h), htype)
        self.assertIsNone(_hash_type("bad"))
        self.assertRaises(ValueError, test_func, "bad")
        self.assertIsNone(test_func(TEST_HASHES['sha1']))
        self.assertRaises(ValueError, test_func, TEST_HASHES['md5'])
        self.assertIsNone(test_func(TEST_HASHES['sha256']))

    def test_hash_anchoring(self):
        # a longer hexadecimal string must not be accepted as a shorter hash type
        for h in ["0" * 33, "0" * 63, "0" * 65, "0" * 129, TEST_HASHES['md5'] + "z"]:
            self.assertRaises(ValueError, _valid_hash, h)
        self.assertRaises(ValueError, _valid_hash, TEST_HASHES['sha256'], "md5")

    def test_hashtype_on_method(self):
        c = DummyAPI(api_key=API_KEY)
        hashtype("sha256")(lambda self, hash: None)(c, HASH)
        self.assertEqual(c.hash, HASH)


class TestServerMessage(TestCase):
    def test_messages(self):
        for data, msg in [({'errors': [{'code': 4, 'message': "Invalid API key"}]}, "Invalid API key"),
                          ({'error': {'code': 401000, 'messages': ["Unauthorized"]}}, "Unauthorized"),
                          ({'error': "invalid_header", 'description': "Unable to parse"}, "Unable to parse"),
                          ({'detail': "Invalid token."}, "Invalid token."),
                          ({'query_status': "unknown_auth_key"}, "unknown_auth_key"),
                          ({'error': {'messages': []}, 'message': "fallback"}, None),
                          ({'code': 4}, None), ([1, 2], None)]:
            self.assertEqual(_server_message(_json(data)), msg)
        self.assertIsNone(_server_message(_response(b"not JSON")))


class TestBase(TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.file = os.path.join(self.tmp, "tmp-file")

    def tearDown(self):
        self._tmp.cleanup()

    def test_base_client_class(self):
        c = DummyClient(test="ok")
        self.assertEqual(c.name, "dummyclient")
        self.assertEqual(getattr(c, "_test", None), "ok")
        self.assertTrue(c.enabled)
        c.content = b"dGVzdA"                     # will fail with logging message
        self.assertIsNotNone(c._decode("base64"))
        c.content = "dGVzdA=="                    # will succeed (str content is encoded first)
        self.assertIsNotNone(c._decode("base64"))
        self.assertEqual(c.content, b"test")
        with self.assertLogs("malsearch", "ERROR"):
            self.assertIsNotNone(c._unzip())      # not an archive
        self.assertIsNotNone(c._save(self.file))  # will succeed
        with open(self.file, 'rb') as f:
            self.assertEqual(f.read(), b"test")
        delattr(c, "content")
        self.assertIsNotNone(c._save(self.file))  # no content, silently (not in error mode)
        self.assertIsNotNone(c._unzip())          # idem
        c._error = True
        with self.assertLogs("malsearch", "ERROR"):
            c._save(self.file)
        with self.assertLogs("malsearch", "ERROR"):
            c._unzip()

    def test_decode_failure(self):
        c = DummyClient()
        c.content = 123
        with self.assertLogs("malsearch", "ERROR"):
            c._decode("base64")
        self.assertEqual(c.content, 123)

    def test_save(self):
        c = DummyClient(output_dir=self.tmp)
        c.hash, c.content = HASH, DATA
        with self.assertNoLogs("malsearch", "WARNING"):
            c._save()
        c.content = b"other"
        with self.assertLogs("malsearch", "WARNING") as logs:
            c._save()
        self.assertIn("content and hash mismatch", logs.output[0])
        # no post-check
        c._postcheck = False
        with self.assertNoLogs("malsearch", "WARNING"):
            c._save()
        # unexpected error (output directory does not exist)
        c._output_dir = os.path.join(self.tmp, "does-not-exist")
        with self.assertLogs("malsearch", "ERROR"):
            c._save()

    def test_unzip(self):
        c = DummyClient()
        for archive in [_zip(("sample", DATA), ("other", b"other")), _zip(("sample", DATA), password=b"infected")]:
            c.content = archive
            c._unzip(b"infected")
            self.assertEqual(c.content, DATA)

    def test_extract(self):
        c = DummyClient()
        c.hash = HASH
        # the sample itself, not an archive
        c.content = DATA
        self.assertEqual(c._extract(b"infected").content, DATA)
        # the matching file is extracted, whatever its position and protection
        for archive in [_zip(("other", b"other"), ("sample", DATA)), _zip(("sample", DATA), password=b"infected")]:
            c.content = archive
            self.assertEqual(c._extract(b"infected").content, DATA)
        # wrong password or no matching file: the content is left untouched
        for archive in [_zip(("sample", DATA), password=b"other"), _zip(("other", b"other"))]:
            c.content = archive
            self.assertEqual(c._extract(b"infected").content, archive)
        # an archive that is the sample itself (e.g. an APK)
        c.content = apk = _zip(("classes.dex", b"content"))
        c.hash = hashlib.sha256(apk).hexdigest()
        self.assertEqual(c._extract(b"infected").content, apk)
        # not a valid archive
        c.content = b"PK not an archive"
        c.hash = HASH
        self.assertEqual(c._extract().content, b"PK not an archive")

    def test_enabled(self):
        c = DummyClient(config=ConfigParser())
        self.assertTrue(c.enabled)
        c._config.read_string("[Disabled]\nother = x\n")
        self.assertTrue(c.enabled)
        c._config['Disabled']['dummyclient'] = "x"
        self.assertFalse(c.enabled)


class TestAPI(TestCase):
    def setUp(self):
        API._disabled.clear()
        API._missing_key.discard("dummyapi")
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = ConfigParser()
        self.conf.path = os.path.join(self.tmp, "malsearch.conf")

    def tearDown(self):
        API._disabled.clear()
        self._tmp.cleanup()

    def _client(self, **kwargs):
        return DummyAPI(api_key=API_KEY, output_dir=self.tmp, config=self.conf, **kwargs)

    def test_request(self):
        with mock.patch("requests.get", return_value=_response(DATA)) as get:
            self._client().get_file_by_hash(HASH)
        # the default headers are merged with the API key header
        get.assert_called_once_with(f"https://api.example.com/files/{HASH}", params=None,
                                    headers={'Accept': "application/json", 'X-Key': API_KEY})
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)
        # explicit headers take precedence over the default ones
        with mock.patch("requests.post", return_value=_json({'content': "data"})) as post:
            c = self._client()._post("path", json={'a': 1}, headers={'Accept': "text/plain"})
        post.assert_called_once_with("https://api.example.com/path", data=None, json={'a': 1},
                                     headers={'Accept': "text/plain", 'X-Key': API_KEY})
        # a "content" field of a JSON response becomes the content
        self.assertEqual(c.content, "data")

    def test_missing_key(self):
        c = DummyAPI(output_dir=self.tmp)
        with mock.patch("requests.get") as get, self.assertLogs("malsearch", "WARNING") as logs:
            self.assertRaises(ServiceUnavailable, c.get_file_by_hash, HASH)
            self.assertRaises(ServiceUnavailable, c.get_file_by_hash, HASH)
        get.assert_not_called()
        # warned only once
        self.assertEqual(logs.output, ["WARNING:malsearch:Did you forget to set up the API key for client 'dummyapi' ?"])

    def test_conditions(self):
        c = self._client()
        c._pre_condition = lambda: False
        with mock.patch("requests.get") as get:
            self.assertRaises(HashNotFoundError, c.get_file_by_hash, HASH)
        get.assert_not_called()
        c = self._client()
        c._post_condition = lambda: c.json.get('status') != "not_found"
        with mock.patch("requests.get", return_value=_json({'status': "not_found"})):
            self.assertRaises(HashNotFoundError, c.get_file_by_hash, HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_stale_json(self):
        c = self._client()
        with mock.patch("requests.get", return_value=_json({'status': "ok"})):
            c._get("path")
        with mock.patch("requests.get", return_value=_response(DATA)):
            c._get("path")
        self.assertFalse(hasattr(c, "json"))

    def test_network_error(self):
        e = exceptions.ConnectionError(f"Max retries exceeded with url: /files?apikey={API_KEY}")
        with mock.patch("requests.get", side_effect=e), self.assertNoLogs("malsearch", "DEBUG"):
            with self.assertRaises(ServiceUnavailable) as ctx:
                self._client().get_file_by_hash(HASH)
        self.assertNotIn(API_KEY, str(ctx.exception))
        self.assertIn("ConnectionError", str(ctx.exception))

    def test_http_errors(self):
        with mock.patch("requests.get", return_value=_response(b"", 404, "Not Found")):
            self.assertRaises(HashNotFoundError, self._client().get_file_by_hash, HASH)
        with mock.patch("requests.get", return_value=_response(b"", 502, "Bad Gateway")):
            with self.assertRaises(ServiceUnavailable) as ctx:
                self._client().get_file_by_hash(HASH)
        self.assertIn("502 - Bad Gateway", str(ctx.exception))
        # other errors are only logged, without the URL
        with mock.patch("requests.get", return_value=_response(b"", 418, "I'm a teapot")), \
             self.assertLogs("malsearch", "ERROR") as logs:
            self._client()._get("path", params={'apikey': API_KEY})
        self.assertEqual(logs.output, ["ERROR:malsearch:dummyapi returned 418 - I'm a teapot"])
        self.assertEqual(API._disabled, {})

    def test_rate_limit(self):
        for headers, seconds in [({'Retry-After': "60"}, 60), ({}, 300), ({'Retry-After': "soon"}, 300)]:
            API._disabled.clear()
            r = _response(b"", 429, "Too Many Requests", headers)
            before = dt.datetime.now()
            with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "WARNING") as logs:
                self.assertRaises(ServiceUnavailable, self._client().get_file_by_hash, HASH)
            self.assertIn("hit its rate limit or quota (429 - Too Many Requests)", logs.output[0])
            until = API._disabled['dummyapi']
            self.assertTrue(before + dt.timedelta(seconds=seconds) <= until <=
                            dt.datetime.now() + dt.timedelta(seconds=seconds))
            # also recorded in the configuration file
            c = ConfigParser()
            c.read(self.conf.path)
            self.assertEqual(c['Disabled']['dummyapi'], f"{until:%d/%m/%Y %H:%M:%S}")
        # a client-specific backoff applies when the service does not tell
        API._disabled.clear()
        c = self._client()
        c.backoff = 10
        with mock.patch("requests.get", return_value=_response(b"", 429, "Too Many Requests")), \
             self.assertLogs("malsearch", "WARNING"):
            self.assertRaises(ServiceUnavailable, c.get_file_by_hash, HASH)
        self.assertLess(API._disabled['dummyapi'], dt.datetime.now() + dt.timedelta(seconds=11))

    def test_invalid_key(self):
        r = _json({'message': "Invalid API key"}, 403, "Forbidden")
        with mock.patch("requests.get", return_value=r) as get, self.assertLogs("malsearch", "WARNING") as logs:
            self.assertRaises(ServiceUnavailable, self._client().get_file_by_hash, HASH)
            # disabled in memory, hence other requests stop without contacting the service nor warning again
            with self.assertRaises(ServiceUnavailable) as ctx:
                self._client().get_file_by_hash(HASH)
        get.assert_called_once()
        self.assertIn("disabled until", str(ctx.exception))
        self.assertEqual(len(logs.output), 1)
        self.assertIn("rejected the API key (403 - Forbidden)", logs.output[0])
        self.assertIn("server said: Invalid API key", logs.output[0])
        # without configuration
        API._disabled.clear()
        with mock.patch("requests.get", return_value=r), self.assertLogs("malsearch", "WARNING"):
            self.assertRaises(ServiceUnavailable, DummyAPI(api_key=API_KEY).get_file_by_hash, HASH)
        self.assertIn("dummyapi", API._disabled)

    def test_no_key_required(self):
        c = DummyAPI(output_dir=self.tmp)
        c._requires_key = False
        with mock.patch("requests.get", return_value=_response(DATA)) as get:
            c.get_file_by_hash(HASH)
        # no API key header
        get.assert_called_once_with(f"https://api.example.com/files/{HASH}", params=None,
                                    headers={'Accept': "application/json"})


class TestWeb(TestCase):
    def test_get(self):
        bs4 = types.ModuleType("bs4")
        bs4.BeautifulSoup = mock.Mock(return_value="soup")
        with mock.patch.dict(sys.modules, {'bs4': bs4}):
            with mock.patch("requests.get", return_value=_response(b"<html></html>")) as get:
                self.assertEqual(Web()._get("https://example.com", params={'q': 1}), "soup")
            get.assert_called_once_with("https://example.com", params={'q': 1}, headers=None)
            bs4.BeautifulSoup.assert_called_once_with(b"<html></html>", "html.parser")
            with mock.patch("requests.get", return_value=_response(b"", 500, "Internal Server Error")):
                self.assertIsNone(Web()._get("https://example.com"))
