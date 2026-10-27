# URLhaus

URLhaus is abuse.ch's project for sharing malware distribution URLs and the payloads they serve.

| | |
|:--|:--|
| **Website** | [urlhaus.abuse.ch](https://urlhaus.abuse.ch) |
| **API documentation** | [urlhaus-api.abuse.ch](https://urlhaus-api.abuse.ch) |
| **Name in configuration** | `urlhaus` |
| **Python class** | `malsearch.URLhaus` |
| **Authentication** | Abuse.ch Auth-Key, sent in the `Auth-Key` header |
| **Download by** | SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

An abuse.ch Auth-Key (free). The same key works for [Malware Bazaar](malwarebazaar.md).

In the [configuration file](../configuration.md):

```ini
[API keys]
urlhaus = YOUR-KEY
```

## Command line

```sh
# download a sample with URLhaus only
malsearch <sha256> --select urlhaus -o samples

# download the samples of URLhaus's feed with URLhaus only
malsearch -m --select urlhaus -o samples

# use every configured client except URLhaus
malsearch <sha256> --skip urlhaus -o samples
```

The feed gives the SHA256 hashes of the payloads of the past 3 days (at most 1000).

## Python

```python
from malsearch import URLhaus

client = URLhaus(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>

for h in client.get_malware_feed():
    print(h)
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Payloads come in a ZIP archive protected by the password `infected` and are extracted before being saved.
