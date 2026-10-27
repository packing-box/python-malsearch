# theZoo

theZoo is a GitHub repository of live malware samples, stored in password-protected archives.

| | |
|:--|:--|
| **Website** | [github.com/ytisf/theZoo](https://github.com/ytisf/theZoo) |
| **API documentation** | [github.com/ytisf/theZoo](https://github.com/ytisf/theZoo) |
| **Name in configuration** | `thezoo` |
| **Python class** | `malsearch.TheZoo` |
| **Authentication** | None (public GitHub repository) |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

None. List the client with an empty value (`thezoo =`) in the `API keys` section to use it.

In the [configuration file](../configuration.md):

```ini
[API keys]
thezoo =
```

## Command line

```sh
# download a sample with theZoo only
malsearch <sha256> --select thezoo -o samples

# download the samples of theZoo's feed with theZoo only
malsearch -m --select thezoo -o samples

# use every configured client except theZoo
malsearch <sha256> --skip thezoo -o samples
```

The feed gives the SHA256 hashes of all the indexed samples.

## Python

```python
from malsearch import TheZoo

client = TheZoo(output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256

for h in client.get_malware_feed():
    print(h)
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- theZoo only publishes the hashes of its archives, not of the samples inside. On first use, MalSearch downloads every archive listed in theZoo's `maldb.db` (about 420 MB, which takes several minutes) and builds an index of the sample hashes in the user cache directory (`~/.cache/malsearch/thezoo.json` on Linux). Later runs only download the archives that changed.
- Only the binaries are indexed (`malware/Binaries`), not the source code archives (`malware/Source`).
- Each archive is opened with its own password (from its `.pass` file), or `infected` by default.
- If the index cannot be updated (e.g. no network access), MalSearch uses the cached index with a warning.
