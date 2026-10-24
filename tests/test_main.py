#!/usr/bin/python
# -*- coding: UTF-8 -*-
import logging
import os
from tempfile import TemporaryDirectory
from unittest import mock, TestCase

from malsearch.__main__ import main


HASHES = ["098f6bcd4621d373cade4e832627b4f6", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]


class TestMain(TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.conf = os.path.join(self.tmp, "malsearch.conf")
        with open(self.conf, 'w') as f:
            f.write("[API keys]\nmalwarebazaar = key\n")
        self.out = os.path.join(self.tmp, "samples")

    def tearDown(self):
        self._tmp.cleanup()

    def _main(self, *args, cache=False):
        argv = ["malsearch", *args, "-c", self.conf, "-o", self.out] + [[], ["--disable-cache"]][not cache]
        # main() imports these from malsearch.__init__ at call time
        with mock.patch("sys.argv", argv), mock.patch("malsearch.__init__.download_samples") as download, \
             mock.patch("malsearch.__init__.get_samples_feed", return_value=iter([HASHES[1] + "\n"])) as feed, \
             mock.patch("requests_cache.install_cache") as cache:
            main()
        return download, feed, cache

    def test_hashes(self):
        download, feed, cache = self._main(HASHES[0].upper(), HASHES[1], "--select", "malwarebazaar")
        self.assertTrue(os.path.isdir(self.out))
        feed.assert_not_called()
        cache.assert_not_called()
        args, kwargs = download.call_args
        self.assertEqual(args, (HASHES[0], HASHES[1]))
        self.assertEqual(kwargs['select'], ["malwarebazaar"])
        self.assertEqual(kwargs['output_dir'], self.out)
        self.assertEqual(kwargs['config'].path, self.conf)

    def test_hash_file_and_feed(self):
        p = os.path.join(self.tmp, "hashes.txt")
        with open(p, 'w') as f:
            f.write(f"{HASHES[0]}\n")
        download, feed, _ = self._main("-f", p, "-m")
        feed.assert_called_once()
        self.assertEqual(download.call_args.args, (HASHES[0], HASHES[1]))

    def test_nothing_to_download(self):
        with self.assertLogs("malsearch", "WARNING") as logs:
            download, _, _ = self._main()
        download.assert_not_called()
        self.assertEqual(logs.output, ["WARNING:malsearch:nothing to download"])

    def test_invalid_arguments(self):
        for args in [["bad-hash"], ["-c", os.path.join(self.tmp, "does-not-exist")], ["-f", "does-not-exist"]]:
            with mock.patch("sys.argv", ["malsearch", *args]), mock.patch("sys.stderr"), \
                 self.assertRaises(SystemExit):
                main()

    def test_cache_and_verbose(self):
        _, _, cache = self._main(HASHES[0], "-v", cache=True)
        cache.assert_called_once()
        self.assertEqual(cache.call_args.args, ("malsearch", ))
        # API keys never end up in the cache keys
        self.assertEqual(cache.call_args.kwargs['ignored_parameters'], ['api_key', 'apikey'])
        # third-party loggers would otherwise log request URLs, hence possibly API keys
        for name in ["charset_normalizer", "requests_cache", "urllib3"]:
            self.assertEqual(logging.getLogger(name).level, logging.WARNING)
