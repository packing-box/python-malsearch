#!/usr/bin/python
# -*- coding: UTF-8 -*-
import hashlib
import os
import struct
import zlib
from configparser import ConfigParser
from requests import Response
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch import download_sample, Sorel20M
from malsearch.clients.__common__ import API


URL = "https://sorel-20m.s3.amazonaws.com/09-DEC-2020/binaries"


def _pe(machine, subsystem, magic=0x10b):
    """ Minimal PE layout: DOS header pointing to the PE signature, file header, then optional header. """
    dos = b"MZ" + b"\0" * 0x3a + struct.pack("<I", 0x40)
    opt = struct.pack("<H", magic) + b"\0" * 66 + struct.pack("<H", subsystem) + b"\0" * 154
    return dos + b"PE\0\0" + struct.pack("<H", machine) + b"\0" * 18 + opt + b"fake section content"


def _response(content=b"", status=200, reason="OK"):
    r = Response()
    r.status_code, r._content, r.reason = status, content, reason
    return r


class TestSorel20M(TestCase):
    def setUp(self):
        API._disabled.clear()
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        # no API key, the client only needs to be listed
        with open(self.conf, 'w') as f:
            f.write("[API keys]\nsorel20m =\n")

    def tearDown(self):
        self._tmp.cleanup()

    def _read(self, h):
        with open(os.path.join(self.tmp, h), 'rb') as f:
            return f.read()

    def test_download(self):
        for machine, subsystem, magic in [(0x14c, 2, 0x10b), (0x14c, 3, 0x10b), (0x8664, 2, 0x20b), (0x1c4, 9, 0x10b)]:
            data = _pe(machine, subsystem, magic)
            h = hashlib.sha256(data).hexdigest()
            with mock.patch("requests.get", return_value=_response(zlib.compress(_pe(0, 0, magic)))) as get, \
                 self.assertNoLogs("malsearch", "WARNING"):
                Sorel20M(output_dir=self.tmp).get_file_by_hash(h)
            # no key nor header sent
            get.assert_called_once_with(f"{URL}/{h}", params=None, headers=None)
            self.assertEqual(self._read(h), data)

    def test_download_from_config(self):
        data = _pe(0x14c, 2)
        h = hashlib.sha256(data).hexdigest()
        with mock.patch("requests.get", return_value=_response(zlib.compress(_pe(0, 0)))):
            self.assertIsNotNone(download_sample(h, config=self.conf, output_dir=self.tmp))
        self.assertEqual(self._read(h), data)

    def test_not_armed(self):
        # content that already matches the hash is saved as is
        data = _pe(0x14c, 2)
        h = hashlib.sha256(data).hexdigest()
        with mock.patch("requests.get", return_value=_response(zlib.compress(data))):
            Sorel20M(output_dir=self.tmp).get_file_by_hash(h)
        self.assertEqual(self._read(h), data)

    def test_cannot_rearm(self):
        # unknown original values: the disarmed sample is saved anyway, with a single warning
        disarmed = _pe(0, 0)
        h = hashlib.sha256(_pe(0x1234, 2)).hexdigest()
        with mock.patch("requests.get", return_value=_response(zlib.compress(disarmed))), \
             self.assertLogs("malsearch", "WARNING") as logs:
            c = Sorel20M(output_dir=self.tmp)
            c.get_file_by_hash(h)
        self.assertEqual(len(logs.output), 1)
        self.assertIn("saved disarmed", logs.output[0])
        self.assertTrue(c._postcheck)
        self.assertEqual(self._read(h), disarmed)

    def test_hash_not_found(self):
        h = "0" * 64
        with mock.patch("requests.get", return_value=_response(b"<Error><Code>NoSuchKey</Code></Error>", 404,
                                                               "Not Found")):
            self.assertRaises(HashNotFoundError, Sorel20M(output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))

    def test_unexpected_content(self):
        h = "0" * 64
        for r in [_response(b"not zlib data"), _response(b"<Error><Code>AccessDenied</Code></Error>", 403,
                                                         "Forbidden")]:
            with mock.patch("requests.get", return_value=r):
                self.assertRaises(ServiceUnavailable, Sorel20M(output_dir=self.tmp).get_file_by_hash, h)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, h)))
        # a 403 is not about any API key, hence the client is not disabled
        self.assertEqual(API._disabled, {})

    def test_unsupported_hash(self):
        with mock.patch("requests.get") as get:
            self.assertRaises(ValueError, Sorel20M().get_file_by_hash, "0" * 32)
        get.assert_not_called()
