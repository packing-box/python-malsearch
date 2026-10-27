# ANY.RUN

ANY.RUN is an interactive malware sandbox. MalSearch finds samples through its Threat Intelligence (TI) Lookup.

| | |
|:--|:--|
| **Website** | [any.run](https://any.run) |
| **API documentation** | [any.run/api-documentation/](https://any.run/api-documentation/) |
| **Name in configuration** | `anyrun` |
| **Python class** | `malsearch.AnyRun` |
| **Authentication** | API key, sent in the `Authorization: API-Key <key>` header |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key with a **TI Lookup** license. Without this license, ANY.RUN answers `402` and MalSearch disables the client for a while.

In the [configuration file](../configuration.md):

```ini
[API keys]
anyrun = YOUR-KEY
```

## Command line

```sh
# download a sample with ANY.RUN only
malsearch <sha256> --select anyrun -o samples

# use every configured client except ANY.RUN
malsearch <sha256> --skip anyrun -o samples
```

## Python

```python
from malsearch import AnyRun

client = AnyRun(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- MalSearch first searches the hash in TI Lookup, then takes the download link either from the files seen in the matching tasks or from the report of a task whose main object is the sample.
- The download link is only followed if it uses HTTPS on an `any.run` host, because the API key is sent with it.
- A sample that comes in a ZIP archive is extracted with the password `infected`, unless the downloaded file already matches the hash (e.g. an APK, which is a ZIP itself).
