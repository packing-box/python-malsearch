# AndroZoo

AndroZoo is a collection of Android applications (APK) gathered from several markets, mostly for research purposes.

| | |
|:--|:--|
| **Website** | [androzoo.uni.lu](https://androzoo.uni.lu) |
| **API documentation** | [androzoo.uni.lu/api_doc](https://androzoo.uni.lu/api_doc) |
| **Name in configuration** | `androzoo` |
| **Python class** | `malsearch.AndroZoo` |
| **Authentication** | API key, sent as the `apikey` URL parameter |
| **Download by** | SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key, granted on request.

In the [configuration file](../configuration.md):

```ini
[API keys]
androzoo = YOUR-KEY
```

## Command line

```sh
# download a sample with AndroZoo only
malsearch <sha256> --select androzoo -o samples

# use every configured client except AndroZoo
malsearch <sha256> --skip androzoo -o samples
```

## Python

```python
from malsearch import AndroZoo

client = AndroZoo(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Only Android applications (APK) are available.
- AndroZoo asks for at most about 20 concurrent downloads. MalSearch enforces this limit across all its download threads.
- An APK is itself a ZIP archive, so it is saved as downloaded.
