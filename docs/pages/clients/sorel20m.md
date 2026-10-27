# SOREL-20M

SOREL-20M is a static dataset of about 10 million Windows PE malware samples published by Sophos and ReversingLabs in December 2020.

| | |
|:--|:--|
| **Website** | [github.com/sophos/SOREL-20M](https://github.com/sophos/SOREL-20M) |
| **API documentation** | [github.com/sophos/SOREL-20M](https://github.com/sophos/SOREL-20M) |
| **Name in configuration** | `sorel20m` |
| **Python class** | `malsearch.Sorel20M` |
| **Authentication** | None (public bucket) |
| **Download by** | SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

None. List the client with an empty value (`sorel20m =`) in the `API keys` section to use it.

In the [configuration file](../configuration.md):

```ini
[API keys]
sorel20m =
```

## Command line

```sh
# download a sample with SOREL-20M only
malsearch <sha256> --select sorel20m -o samples

# use every configured client except SOREL-20M
malsearch <sha256> --skip sorel20m -o samples
```

## Python

```python
from malsearch import Sorel20M

client = Sorel20M(output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Only Windows PE files are available, and the dataset is not updated.
- The samples are stored zlib-compressed and *disarmed*: their `FileHeader.Machine` and `OptionalHeader.Subsystem` fields are set to zero so that they cannot run. MalSearch decompresses them and restores both fields by trying the possible values until the file matches the hash again.
- If the fields cannot be restored, the sample is still saved (disarmed) for static analysis, with a warning.
