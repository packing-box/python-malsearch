#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
from malsearch import *
from unittest import TestCase


CONF = """[API keys]
VirusTotal = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
[Disabled]
VirusTotal = Bad API key
"""
FILE = "test.conf"
HASH = "098f6bcd4621d373cade4e832627b4f6"


class TestInit(TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FILE, 'w') as f:
            f.write(CONF)
    
    @classmethod
    def tearDownClass(cls):
        os.remove(FILE)
    
    def test_config(self):
        from malsearch.__init__ import _valid_conf
        self.assertRaises(ValueError, _valid_conf, "does_not_exist")
        self.assertIsNotNone(_valid_conf(FILE))
    
    def test_download(self):
        self.assertIsNone(download_sample(HASH))
        self.assertIsNone(download_sample(HASH, FILE))
        self.assertIsNone(download_samples())

