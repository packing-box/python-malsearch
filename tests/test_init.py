#!/usr/bin/python
# -*- coding: UTF-8 -*-
import datetime as dt
import hashlib
import os
import sys
from configparser import ConfigParser
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import *
from malsearch.__init__ import _valid_conf, _valid_hash_file
from malsearch.clients.__common__ import API


CONF = """[API keys]
VirusTotal = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
[Disabled]
VirusTotal = Bad API key
"""
HASH = "098f6bcd4621d373cade4e832627b4f6"
DATA = b"MZ fake sample"
SHA256 = hashlib.sha256(DATA).hexdigest()


def _fake_download(self, hash):
    self.hash, self.content = hash, DATA
    self._save()


class TestInit(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        self._write(CONF)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, content):
        with open(self.conf, 'w') as f:
            f.write(content)

    def _read(self):
        c = ConfigParser()
        c.read(self.conf)
        return c

    def test_config(self):
        self.assertRaises(ValueError, _valid_conf, os.path.join(self.tmp, "does_not_exist"))
        self.assertEqual(_valid_conf(self.conf).path, self.conf)
        self._write("not an INI file")
        self.assertRaises(ValueError, _valid_conf, self.conf)

    def test_hash_file(self):
        p = os.path.join(self.tmp, "hashes.txt")
        self.assertRaises(ValueError, _valid_hash_file, p)
        with open(p, 'w') as f:
            f.write(f"{HASH.upper()}\n{SHA256}\n")
        self.assertEqual(_valid_hash_file(p), [HASH, SHA256])
        with open(p, 'a') as f:
            f.write("bad\n")
        self.assertRaises(ValueError, _valid_hash_file, p)

    def test_download(self):
        with self.assertLogs("malsearch", "ERROR"):
            self.assertIsNone(download_sample(HASH))
        # the only client is disabled until its entry is removed
        with self.assertLogs("malsearch", "WARNING") as logs:
            self.assertIsNone(download_sample(HASH, config=self.conf))
        self.assertIn("WARNING:malsearch:virustotal is disabled", logs.output)
        self.assertIsNone(download_samples())

    def test_download_found(self):
        self._write("[API keys]\nmalshare = key\nmalwarebazaar = key\n")
        with mock.patch.object(MalShare, "get_file_by_hash", side_effect=HashNotFoundError(SHA256, "MalShare")), \
             mock.patch.object(MalwareBazaar, "get_file_by_hash", _fake_download), \
             self.assertLogs("malsearch", "INFO") as logs:
            c = download_sample(SHA256, config=self.conf, output_dir=self.tmp)
        self.assertIsInstance(c, MalwareBazaar)
        self.assertIn(f"INFO:malsearch:found {SHA256} on MalwareBazaar !", logs.output)
        # already downloaded
        with mock.patch.object(MalwareBazaar, "get_file_by_hash") as get, self.assertLogs("malsearch", "INFO") as logs:
            self.assertIsNone(download_sample(SHA256, config=self.conf, output_dir=self.tmp))
        get.assert_not_called()
        self.assertIn("already exists", logs.output[-1])
        # unless overwriting
        with mock.patch.object(MalwareBazaar, "get_file_by_hash", _fake_download):
            self.assertIsNotNone(download_sample(SHA256, config=self.conf, output_dir=self.tmp, overwrite=True))

    def test_download_errors(self):
        # every kind of failure is caught so that the next client is tried
        self._write("[API keys]\nmaldatabase = key\nmalpedia = key\nmalshare = key\nmalwarebazaar = key\n"
                    "virusshare = key\n")
        with mock.patch.object(Malpedia, "get_file_by_hash", side_effect=AttributeError("no content")), \
             mock.patch.object(MalShare, "get_file_by_hash", side_effect=ServiceUnavailable("MalShare")), \
             mock.patch.object(MalwareBazaar, "get_file_by_hash", side_effect=RuntimeError("unexpected")), \
             mock.patch.object(VirusShare, "get_file_by_hash", _fake_download), \
             self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertIsInstance(download_sample(SHA256, config=self.conf, output_dir=self.tmp), VirusShare)
        log = "\n".join(logs.output)
        self.assertIn("MalShare seems to be currently unavailable", log)
        self.assertIn("unexpected", log)
        # Maldatabase has no get_file_by_hash, hence it is not even tried
        self.assertNotIn("trying maldatabase", log)

    def test_select_skip(self):
        self._write("[API keys]\nmalshare = key\nmalwarebazaar = key\n")
        with mock.patch.object(MalShare, "get_file_by_hash") as ms, \
             mock.patch.object(MalwareBazaar, "get_file_by_hash") as mb, self.assertLogs("malsearch", "DEBUG") as logs:
            download_sample(SHA256, config=self.conf, output_dir=self.tmp, skip=["malshare"])
            download_sample(SHA256, config=self.conf, output_dir=self.tmp, select=["malshare"])
        self.assertEqual((ms.call_count, mb.call_count), (1, 1))
        self.assertIn("DEBUG:malsearch:malshare skipped", logs.output)
        # a selected client without a key is created so that the user gets warned
        API._missing_key.discard("virustotal")
        with mock.patch("requests.get") as get, self.assertLogs("malsearch", "WARNING") as logs:
            download_sample(SHA256, config=self.conf, output_dir=self.tmp, select=["virustotal"])
        get.assert_not_called()
        self.assertIn("WARNING:malsearch:Did you forget to set up the API key for client 'virustotal' ?", logs.output)

    def test_disabled(self):
        past = f"{dt.datetime.now() - dt.timedelta(minutes=1):%d/%m/%Y %H:%M:%S}"
        future = f"{dt.datetime.now() + dt.timedelta(hours=1):%d/%m/%Y %H:%M:%S}"
        self._write(f"[API keys]\nmalshare = key\nmalwarebazaar = key\nvirusshare = key\n"
                    f"[Disabled]\nmalshare = {past}\nmalwarebazaar = {future}\nvirusshare = until I say so\n")
        with mock.patch.object(MalShare, "get_file_by_hash") as ms, \
             mock.patch.object(MalwareBazaar, "get_file_by_hash") as mb, \
             mock.patch.object(VirusShare, "get_file_by_hash") as vs, self.assertLogs("malsearch", "WARNING") as logs:
            download_sample(SHA256, config=self.conf, output_dir=self.tmp)
        # expired: re-enabled and removed from the configuration file
        self.assertEqual((ms.call_count, mb.call_count, vs.call_count), (1, 0, 0))
        self.assertEqual(list(self._read()['Disabled']), ["malwarebazaar", "virusshare"])
        self.assertIn(f"WARNING:malsearch:malwarebazaar is disabled until {future}", logs.output)
        self.assertIn("WARNING:malsearch:virusshare is disabled", logs.output)

    def test_download_samples(self):
        self._write("[API keys]\nmalwarebazaar = key\n")
        hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
        with mock.patch.object(MalwareBazaar, "get_file_by_hash") as get, self.assertLogs("malsearch", "WARNING"):
            download_samples(hashes[0].upper(), config=self.conf, output_dir=self.tmp)
        get.assert_called_once_with(hashes[0])
        # in parallel, with or without tqdm
        for tqdm in [mock.DEFAULT, None]:
            with mock.patch.dict(sys.modules, {'tqdm': None} if tqdm is None else {}), \
                 mock.patch.object(MalwareBazaar, "get_file_by_hash") as get, self.assertLogs("malsearch", "WARNING"):
                download_samples(*hashes, config=self.conf, output_dir=self.tmp, max_workers=2)
            self.assertEqual(sorted(c.args[0] for c in get.call_args_list), sorted(hashes))

    def test_feed(self):
        self._write("[API keys]\nmaldatabase = key\nmalshare = key\nmalwarebazaar = key\nvirustotal = key\n")
        with mock.patch.object(Maldatabase, "get_malware_feed", side_effect=ServiceUnavailable("Maldatabase")), \
             mock.patch.object(MalShare, "get_malware_feed", side_effect=RuntimeError("unexpected")), \
             mock.patch.object(MalwareBazaar, "get_malware_feed", return_value=iter([SHA256, HASH])), \
             self.assertLogs("malsearch", "DEBUG") as logs:
            self.assertEqual(list(get_samples_feed(config=self.conf)), [SHA256, HASH])
        log = "\n".join(logs.output)
        self.assertIn("Maldatabase seems to be currently unavailable", log)
        self.assertIn("unexpected", log)
        self.assertIn("got 2 hashes", log)
        # VirusTotal has no feed, hence it is not even tried
        self.assertNotIn("trying virustotal", log)

    def test_no_client(self):
        self._write("[API keys]\n")
        with self.assertLogs("malsearch", "WARNING") as logs:
            self.assertIsNone(download_sample(SHA256, config=self.conf, output_dir=self.tmp))
        self.assertIn("WARNING:malsearch:no download client available/enabled", logs.output)
