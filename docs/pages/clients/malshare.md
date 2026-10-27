# MalShare

MalShare is a free, community-driven public malware repository.

| | |
|:--|:--|
| **Website** | [malshare.com](https://malshare.com) |
| **API documentation** | [malshare.com/doc.php](https://malshare.com/doc.php) |
| **Name in configuration** | `malshare` |
| **Python class** | `malsearch.MalShare` |
| **Authentication** | API key, sent as the `api_key` URL parameter |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

A free API key (register on MalShare).

In the [configuration file](../configuration.md):

```ini
[API keys]
malshare = YOUR-KEY
```

## Command line

```sh
# download a sample with MalShare only
malsearch <sha256> --select malshare -o samples

# download the samples of MalShare's feed with MalShare only
malsearch -m --select malshare -o samples

# use every configured client except MalShare
malsearch <sha256> --skip malshare -o samples
```

The feed gives the SHA256 hashes of the samples added in the past 24 hours.

## Python

```python
from malsearch import MalShare

client = MalShare(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256

for h in client.get_malware_feed():
    print(h)
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.
