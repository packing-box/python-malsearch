# Triage

Triage is Hatching's (Recorded Future) malware sandbox.

| | |
|:--|:--|
| **Website** | [tria.ge](https://tria.ge) |
| **API documentation** | [tria.ge/docs](https://tria.ge/docs) |
| **Name in configuration** | `triage` |
| **Python class** | `malsearch.Triage` |
| **Authentication** | API key, sent in the `Authorization: Bearer <key>` header |
| **Download by** | MD5, SHA1, SHA256, SHA512 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key.

In the [configuration file](../configuration.md):

```ini
[API keys]
triage = YOUR-KEY
```

## Command line

```sh
# download a sample with Triage only
malsearch <sha256> --select triage -o samples

# use every configured client except Triage
malsearch <sha256> --skip triage -o samples
```

## Python

```python
from malsearch import Triage

client = Triage(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256, SHA512
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- MalSearch searches the hash, then downloads the sample of the first matching analysis.
