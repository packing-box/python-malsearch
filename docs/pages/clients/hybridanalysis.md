# Hybrid Analysis

Hybrid Analysis is a free malware analysis service powered by CrowdStrike Falcon Sandbox.

| | |
|:--|:--|
| **Website** | [hybrid-analysis.com](https://hybrid-analysis.com) |
| **API documentation** | [hybrid-analysis.com/docs/api/v2](https://hybrid-analysis.com/docs/api/v2) |
| **Name in configuration** | `hybridanalysis` |
| **Python class** | `malsearch.HybridAnalysis` |
| **Authentication** | API key, sent in the `api-key` header |
| **Download by** | SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key. Downloading samples requires a **vetted** account.

In the [configuration file](../configuration.md):

```ini
[API keys]
hybridanalysis = YOUR-KEY
```

## Command line

```sh
# download a sample with Hybrid Analysis only
malsearch <sha256> --select hybridanalysis -o samples

# download the samples of Hybrid Analysis's feed with Hybrid Analysis only
malsearch -m --select hybridanalysis -o samples

# use every configured client except Hybrid Analysis
malsearch <sha256> --skip hybridanalysis -o samples
```

The feed gives the SHA256 hashes of the last 250 reports from the past 24 hours (`feed/latest`).

## Python

```python
from malsearch import HybridAnalysis

client = HybridAnalysis(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>

for h in client.get_malware_feed():
    print(h)
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- The default key limits are 5 requests per minute and 200 per hour.
- Samples come gzipped and are decompressed before being saved.
