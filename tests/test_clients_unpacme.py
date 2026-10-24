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

from malsearch import download_sample, get_samples_feed, UnpacMe
from malsearch.clients.__common__ import API


API_KEY = "s3cr3t-k3y"
URL = "https://api.unpac.me/api/v1"
DATA = b"MZ fake packed sample"
HASH = hashlib.sha256(DATA).hexdigest()
LINK = "https://storage.example.com/batch.zip?X-Amz-Signature=abc"


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


def _json(data, status=200, reason="OK"):
    return _response(json.dumps(data).encode(), status, reason)


def _zip(*files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        for name, data in files:
            z.writestr(name, data)
    return buffer.getvalue()


class TestUnpacMe(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write(f"[API keys]\nunpacme = {API_KEY}\n")
        # do not wait during tests
        p = mock.patch("time.sleep")
        self.sleep = p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def test_download(self):
        polls = [_json({}), _json({'description': "Not found."}, 404, "NOT FOUND"), _json({'download_url': LINK}),
                 _response(_zip((HASH, DATA)))]
        with mock.patch("requests.post", return_value=_json({'token': "tok"})) as post, \
             mock.patch("requests.get", side_effect=polls) as get:
            UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        post.assert_called_once_with(f"{URL}/private/batch/download", data=None, json={'type': "hash", 'dlist': [HASH]},
                                     headers={'Authorization': f"Key {API_KEY}"})
        poll = mock.call(f"{URL}/private/batch/download/tok", params=None,
                         headers={'Cache-Control': "no-store", 'Authorization': f"Key {API_KEY}"})
        # the job is polled until it gives a link (a 404 meaning not ready yet), then the archive is fetched without key
        self.assertEqual(get.call_args_list, [poll, poll, poll, mock.call(LINK)])
        self.assertEqual(self.sleep.call_count, 2)
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_download_unpacked(self):
        children = {hashlib.sha256(f"unpacked {i}".encode()).hexdigest(): f"unpacked {i}".encode() for i in range(2)}
        c1, c2 = children
        terms = _json({'search_terms': [{'term': "imphash"}, {'term': "sha256"}]})
        search = _json({'results': [{'sha256': HASH, 'analysis': [
            # an analysis where the sample is not the submitted file (e.g. it was unpacked from another one)
            {'id': "other", 'submission_sha256': "f" * 64},
            {'id': "abc", 'submission_sha256': HASH.upper()}]}]})
        results = _json({'id': "abc", 'sha256': HASH, 'results': [
            {'hashes': {'sha256': HASH}}, {'hashes': {'sha256': c1}}, {'hashes': {'sha256': c2}},
            {'hashes': {'sha256': c1}}]})
        # c1 is downloaded, c2 is not available (empty archive) and the sample is downloaded anyway
        gets = [terms, results, _json({'download_url': LINK}), _response(_zip((c1, children[c1]))),
                _json({'download_url': LINK}), _response(_zip()), _json({'download_url': LINK}),
                _response(_zip((HASH, DATA)))]
        posts = [search, _json({'token': "t1"}), _json({'token': "t2"}), _json({'token': "t3"})]
        with mock.patch("requests.post", side_effect=posts) as post, mock.patch("requests.get", side_effect=gets) as get:
            UnpacMe(api_key=API_KEY, output_dir=self.tmp, unpacked=True).get_file_by_hash(HASH)
        self.assertEqual(post.call_args_list[0], mock.call(f"{URL}/private/search/term/sha256", data=None,
                                                           json={'value': HASH},
                                                           headers={'Authorization': f"Key {API_KEY}"}))
        self.assertEqual([c.kwargs['json']['dlist'] for c in post.call_args_list[1:]], [[c1], [c2], [HASH]])
        self.assertEqual(get.call_args_list[1].args, (f"{URL}/private/results/abc", ))
        with open(os.path.join(self.tmp, c1), 'rb') as f:
            self.assertEqual(f.read(), children[c1])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, c2)))
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)
    
    def test_download_unpacked_failure(self):
        # no search term for hashes: no unpacked file but the sample is still downloaded
        gets = [_json({'search_terms': [{'term': "imphash"}]}), _json({'download_url': LINK}),
                _response(_zip((HASH, DATA)))]
        with mock.patch("requests.post", return_value=_json({'token': "tok"})) as post, \
             mock.patch("requests.get", side_effect=gets):
            UnpacMe(api_key=API_KEY, output_dir=self.tmp, unpacked=True).get_file_by_hash(HASH)
        post.assert_called_once()
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)
        # MalwareID-only analysis (no list of files): idem
        search = _json({'results': [{'analysis': [{'id': "abc", 'submission_sha256': HASH}]}]})
        gets = [_json({'search_terms': [{'term': "sha256"}]}), _json({'results': {'x': {}}}),
                _json({'download_url': LINK}), _response(_zip((HASH, DATA)))]
        os.remove(os.path.join(self.tmp, HASH))
        with mock.patch("requests.post", side_effect=[search, _json({'token': "tok"})]), \
             mock.patch("requests.get", side_effect=gets):
            UnpacMe(api_key=API_KEY, output_dir=self.tmp, unpacked=True).get_file_by_hash(HASH)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, HASH)))
    
    def test_download_not_zipped(self):
        # the link may give the file itself
        with mock.patch("requests.post", return_value=_json({'token': "tok"})), \
             mock.patch("requests.get", side_effect=[_json({'download_url': LINK}), _response(DATA)]):
            UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash(HASH)
        with open(os.path.join(self.tmp, HASH), 'rb') as f:
            self.assertEqual(f.read(), DATA)

    def test_download_link_failure(self):
        with mock.patch("requests.post", return_value=_json({'token': "tok"})), \
             mock.patch("requests.get", side_effect=[_json({'download_url': LINK}), _response(b"", 403, "Forbidden")]):
            self.assertRaises(ServiceUnavailable, UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_download_unpacked_no_analysis(self):
        # no analysis where the sample was submitted, or the search fails: the sample is downloaded anyway
        terms = _json({'search_terms': [{'term': "sha256"}]})
        for search in [_json({'results': [{'analysis': [{'id': "other", 'submission_sha256': "f" * 64}]}]}),
                       _response(b"", 503, "Service Unavailable")]:
            with mock.patch("requests.post", side_effect=[search, _json({'token': "tok"})]) as post, \
                 mock.patch("requests.get", side_effect=[terms, _json({'download_url': LINK}),
                                                         _response(_zip((HASH, DATA)))]):
                UnpacMe(api_key=API_KEY, output_dir=self.tmp, unpacked=True, overwrite=True).get_file_by_hash(HASH)
            self.assertEqual(post.call_count, 2)
            with open(os.path.join(self.tmp, HASH), 'rb') as f:
                self.assertEqual(f.read(), DATA)

    def test_hash_not_found(self):
        # no token
        with mock.patch("requests.post", return_value=_json({})), mock.patch("requests.get") as get:
            self.assertRaises(HashNotFoundError, UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, HASH)
        get.assert_not_called()
        # empty archive
        with mock.patch("requests.post", return_value=_json({'token': "tok"})), \
             mock.patch("requests.get", side_effect=[_json({'download_url': LINK}), _response(_zip())]):
            self.assertRaises(HashNotFoundError, UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, HASH)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_job_timeout(self):
        with mock.patch("requests.post", return_value=_json({'token': "tok"})), \
             mock.patch("requests.get", return_value=_json({})) as get:
            self.assertRaises(ServiceUnavailable, UnpacMe(api_key=API_KEY, output_dir=self.tmp).get_file_by_hash, HASH)
        self.assertEqual(get.call_count, UnpacMe._poll_timeout // UnpacMe._poll_interval)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, HASH)))

    def test_unsupported_hash(self):
        with mock.patch("requests.post") as post:
            self.assertRaises(ValueError, UnpacMe(api_key=API_KEY).get_file_by_hash, HASH[:32])
        post.assert_not_called()

    def test_invalid_key(self):
        r = _json({'description': "Unable to parse authentication token.", 'error': "invalid_header"}, 401,
                  "UNAUTHORIZED")
        with mock.patch("requests.post", return_value=r), self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsNone(download_sample(HASH, config=self.conf, output_dir=self.tmp))
        self.assertNotIn(API_KEY, "\n".join(logs.output))
        self.assertTrue(any("rejected the API key" in l and "Unable to parse authentication token." in l
                            for l in logs.output))
        c = ConfigParser()
        c.read(self.conf)
        self.assertIn("unpacme", c['Disabled'])

    def test_feed(self):
        subs = [{'id': str(i), 'submission_sha256': hashlib.sha256(str(i).encode()).hexdigest(), 'children': {}}
                for i in range(3)]
        with mock.patch("requests.get", return_value=_json({'cursor': 1, 'submissions': subs})) as get:
            hashes = list(get_samples_feed(config=self.conf))
        get.assert_called_once_with(f"{URL}/private/feed/unpacked", params=None,
                                    headers={'Authorization': f"Key {API_KEY}"})
        self.assertEqual(hashes, [s['submission_sha256'] for s in subs])
