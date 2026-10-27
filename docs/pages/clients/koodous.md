# Koodous

Koodous is a collaborative platform for Android malware analysis.

| | |
|:--|:--|
| **Website** | [koodous.com](https://koodous.com) |
| **API documentation** | [docs.koodous.com/api/apks.html](https://docs.koodous.com/api/apks.html) |
| **Name in configuration** | `koodous` |
| **Python class** | `malsearch.Koodous` |
| **Authentication** | Token, sent in the `Authorization: Token <token>` header |
| **Download by** | SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API token. The free plan allows no downloads; the paid plans allow 15 (Fan), 300 (Research) or 5000 (Corporate) downloads per day.

In the [configuration file](../configuration.md):

```ini
[API keys]
koodous = YOUR-KEY
```

## Command line

```sh
# download a sample with Koodous only
malsearch <sha256> --select koodous -o samples

# use every configured client except Koodous
malsearch <sha256> --skip koodous -o samples
```

## Python

```python
from malsearch import Koodous

client = Koodous(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Only Android applications (APK) are available.
- The API answers with a download link that is valid for 3 minutes; MalSearch downloads the sample from it right away.
