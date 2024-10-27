#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
from malsearch.clients.__common__ import _valid_hash, hashtype, _Base
from unittest import TestCase

FILE = "tmp-file"
TEST_HASHES = {
    'md5':    "098f6bcd4621d373cade4e832627b4f6",
    'sha1':   "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
    'sha224': "90a3ed9e32b2aaf4c61c410eb925426119e1a9dc53d4286ade99a809",
    'sha256': "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    'sha284': "768412320f7b0aa5812fce428dc4706b3cae50e02a64caa16a782249bfe8efc4b7ef1ccb126255d196047dfedf17a0a9",
    'sha512': "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff",
}


class TestClient(_Base):
    pass


class TestInit(TestCase):
    def test_base_client_class(self):
        c = TestClient(test="ok")
        self.assertEqual(c.name, "testclient")
        self.assertEqual(getattr(c, "_test", None), "ok")
        c.content = b"dGVzdA"                # will fail with logging message
        self.assertIsNotNone(c._decode("base64"))
        c.content = b"dGVzdA=="              # will succeed
        self.assertIsNotNone(c._decode("base64"))
        self.assertEqual(c.content, b"test")
        self.assertIsNotNone(c._unzip())     # will fail with logging message
        self.assertIsNotNone(c._save(FILE))  # will succeed
        delattr(c, "content")
        self.assertIsNotNone(c._save(FILE))  # will fail with logging message
        self.assertIsNotNone(c._unzip())     # will fail with logging message
    
    def test_hash_functions(self):
        @hashtype("sha1", "sha256")
        def test_func(hash):
            pass
        self.assertRaises(ValueError, _valid_hash, "bad")
        for h in TEST_HASHES.values():
            self.assertEqual(_valid_hash(h), h.lower())
        self.assertRaises(ValueError, test_func, "bad")
        self.assertIsNone(test_func(TEST_HASHES['sha1']))
        self.assertRaises(ValueError, test_func, TEST_HASHES['md5'])
        self.assertIsNone(test_func(TEST_HASHES['sha256']))

