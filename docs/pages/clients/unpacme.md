# UnpacMe

UnpacMe is an automated malware unpacking service.

| | |
|:--|:--|
| **Website** | [www.unpac.me](https://www.unpac.me) |
| **API documentation** | [api.unpac.me](https://api.unpac.me) |
| **Name in configuration** | `unpacme` |
| **Python class** | `malsearch.UnpacMe` |
| **Authentication** | API key, sent in the `Authorization: Key <key>` header |
| **Download by** | SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | Yes |

## Requirements

An API key, which requires a **paid** plan. Downloads are limited per month depending on the plan, and the feed requires a plan with feed access.

In the [configuration file](../configuration.md):

```ini
[API keys]
unpacme = YOUR-KEY
```

## Command line

```sh
# download a sample with UnpacMe only
malsearch <sha256> --select unpacme -o samples

# also download the unpacked files of the sample
malsearch <sha256> -u --select unpacme -o samples

# download the samples of UnpacMe's feed with UnpacMe only
malsearch -m --select unpacme -o samples

# use every configured client except UnpacMe
malsearch <sha256> --skip unpacme -o samples
```

The feed gives the SHA256 hashes of the latest page of the feed of unpacked samples.

With `-u` (`--unpacked`), MalSearch also downloads the files that UnpacMe unpacked from the sample, listed in the results of its analysis. They are saved under their own hashes, next to the sample.

## Python

```python
from malsearch import UnpacMe

client = UnpacMe(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>

for h in client.get_malware_feed():
    print(h)
```

To also download the unpacked files:

```python
UnpacMe(api_key="YOUR-KEY", output_dir="samples", unpacked=True).get_file_by_hash("<sha256>")
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- Each file is downloaded through a batch download job: MalSearch requests the job, checks every 2 seconds whether its download link is ready (for at most 60 seconds), then downloads and extracts the archive.
