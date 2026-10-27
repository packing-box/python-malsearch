# Malpedia

Malpedia is a curated reference collection of malware families, run by Fraunhofer FKIE.

| | |
|:--|:--|
| **Website** | [malpedia.caad.fkie.fraunhofer.de](https://malpedia.caad.fkie.fraunhofer.de) |
| **API documentation** | [malpedia.caad.fkie.fraunhofer.de/usage/api](https://malpedia.caad.fkie.fraunhofer.de/usage/api) |
| **Name in configuration** | `malpedia` |
| **Python class** | `malsearch.Malpedia` |
| **Authentication** | API token, sent in the `Authorization: APIToken <token>` header |
| **Download by** | MD5, SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API token (Malpedia accounts are granted on request).

In the [configuration file](../configuration.md):

```ini
[API keys]
malpedia = YOUR-KEY
```

## Command line

```sh
# download a sample with Malpedia only
malsearch <sha256> --select malpedia -o samples

# use every configured client except Malpedia
malsearch <sha256> --skip malpedia -o samples
```

## Python

```python
from malsearch import Malpedia

client = Malpedia(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA256
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Malpedia serves a password-protected archive with the sample and possibly its unpacked or dumped files. MalSearch only keeps the file that matches the requested hash.
