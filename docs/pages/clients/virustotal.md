# VirusTotal

VirusTotal is Google's multi-scanning service.

| | |
|:--|:--|
| **Website** | [www.virustotal.com](https://www.virustotal.com) |
| **API documentation** | [docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview) |
| **Name in configuration** | `virustotal` |
| **Python class** | `malsearch.VirusTotal` |
| **Authentication** | API key, sent in the `x-apikey` header |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | Yes |

## Requirements

A **premium** API key: public keys cannot download samples (VirusTotal answers `403`, and MalSearch disables the client for a while).

In the [configuration file](../configuration.md):

```ini
[API keys]
virustotal = YOUR-KEY
```

## Command line

```sh
# download a sample with VirusTotal only
malsearch <sha256> --select virustotal -o samples

# also download the unpacked files of the sample
malsearch <sha256> -u --select virustotal -o samples

# use every configured client except VirusTotal
malsearch <sha256> --skip virustotal -o samples
```

With `-u` (`--unpacked`), MalSearch also downloads the files whose name, in VirusTotal's report of the sample, has the form `<hash>_unpacked`. They are saved under their own hashes, next to the sample.

## Python

```python
from malsearch import VirusTotal

client = VirusTotal(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256
```

To also download the unpacked files:

```python
VirusTotal(api_key="YOUR-KEY", output_dir="samples", unpacked=True).get_file_by_hash("<sha256>")
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- A sample that comes in a ZIP archive is extracted (trying the password `infected`), unless the downloaded file already matches the hash.
