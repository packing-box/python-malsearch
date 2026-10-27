# PolySwarm

PolySwarm is a threat intelligence marketplace where security engines scan submitted files.

| | |
|:--|:--|
| **Website** | [polyswarm.network](https://polyswarm.network) |
| **API documentation** | [github.com/polyswarm/polyswarm-api](https://github.com/polyswarm/polyswarm-api) |
| **Name in configuration** | `polyswarm` |
| **Python class** | `malsearch.PolySwarm` |
| **Authentication** | API key (32 characters), sent in the `Authorization` header |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key.

In the [configuration file](../configuration.md):

```ini
[API keys]
polyswarm = YOUR-KEY
```

## Command line

```sh
# download a sample with PolySwarm only
malsearch <sha256> --select polyswarm -o samples

# use every configured client except PolySwarm
malsearch <sha256> --skip polyswarm -o samples
```

## Python

```python
from malsearch import PolySwarm

client = PolySwarm(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Samples are downloaded from the `default` community.
- A malformed key (not 32 characters) is rejected like an invalid one, so the client gets disabled for a while.
