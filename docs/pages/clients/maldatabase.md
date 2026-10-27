# Maldatabase

Maldatabase provides malware data feeds. MalSearch only uses its hash feed: it cannot download samples from it.

| | |
|:--|:--|
| **Website** | [maldatabase.com](https://maldatabase.com) |
| **API documentation** | [maldatabase.com/api-doc.html](https://maldatabase.com/api-doc.html) |
| **Name in configuration** | `maldatabase` |
| **Python class** | `malsearch.Maldatabase` |
| **Authentication** | API key, sent in the `Authorization` header |
| **Download by** | *(no download)* |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key.

In the [configuration file](../configuration.md):

```ini
[API keys]
maldatabase = YOUR-KEY
```

## Command line

```sh
# Maldatabase only gives hashes: get them from its feed, and download the samples from the other clients
malsearch -m -o samples
```

`--select maldatabase` would restrict the downloads to Maldatabase too, so no sample would be downloaded.

## Python

```python
from malsearch import Maldatabase

client = Maldatabase(api_key="YOUR-KEY")
for h in client.get_malware_feed():                  # SHA256 by default
    print(h)
for h in client.get_malware_feed(hashtype="md5"):    # also "sha1"
    print(h)
```

To download the samples of the feed with the other clients of your configuration:

```python
from malsearch import download_samples, Maldatabase

hashes = list(Maldatabase(api_key="YOUR-KEY").get_malware_feed())
download_samples(*hashes, config="~/.malsearch.conf", output_dir="samples", skip=["maldatabase"])
```

## Notes

- As Maldatabase cannot download samples, it is skipped when downloading. Combine it with other clients to download the samples of its feed (see the examples above).
- From Python, `get_malware_feed(hashtype=...)` also yields MD5 or SHA1 hashes. The command line always uses SHA256.
