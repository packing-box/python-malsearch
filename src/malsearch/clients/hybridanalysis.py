# -*- coding: UTF-8 -*-
from .__common__ import hashtype, API


__all__ = ["HybridAnalysis"]


class HybridAnalysis(API):
    doc = "https://hybrid-analysis.com/docs/api/v2"
    url = "https://hybrid-analysis.com/api/v2"
    _api_key_header = "api-key"

    def get_malware_feed(self):
        # summary of the last 250 reports from the past 24 hours
        self._get("feed/latest")
        for report in getattr(self, "json", {}).get('data') or []:
            if report.get('sha256'):
                yield report['sha256']

    @hashtype("sha256")
    def get_file_by_hash(self, hash):
        # default key limits: 5 requests/minute and 200/hour ; downloading requires a vetted account
        self._get(f"overview/{hash}/sample")
        # the sample comes gzipped
        if getattr(self, "content", b"")[:2] == b"\x1f\x8b":
            import gzip
            self.content = gzip.decompress(self.content)
        self._save()
