# VirusShare

VirusShare is a large repository of malware samples for security researchers.

| | |
|:--|:--|
| **Website** | [virusshare.com](https://virusshare.com) |
| **API documentation** | [virusshare.com/apiv2_reference](https://virusshare.com/apiv2_reference) |
| **Name in configuration** | `virusshare` |
| **Python class** | `malsearch.VirusShare` |
| **Authentication** | API key, sent as the `apikey` URL parameter |
| **Download by** | MD5, SHA1, SHA224, SHA256, SHA384, SHA512 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key (VirusShare accounts are granted on request).

In the [configuration file](../configuration.md):

```ini
[API keys]
virusshare = YOUR-KEY
```

## Command line

```sh
# download a sample with VirusShare only
malsearch <sha256> --select virusshare -o samples

# use every configured client except VirusShare
malsearch <sha256> --skip virusshare -o samples
```

## Python

```python
from malsearch import VirusShare

client = VirusShare(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA224, SHA256, SHA384, SHA512
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- VirusShare is the only service that accepts every hash type supported by MalSearch.
- Samples come in a ZIP archive protected by the password `infected` and are extracted before being saved.
