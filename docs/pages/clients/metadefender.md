# MetaDefender

MetaDefender Cloud is OPSWAT's multi-scanning service.

| | |
|:--|:--|
| **Website** | [metadefender.opswat.com](https://metadefender.opswat.com) |
| **API documentation** | [www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4](https://www.opswat.com/docs/mdcloud/metadefender-cloud-api-v4) |
| **Name in configuration** | `metadefender` |
| **Python class** | `malsearch.MetaDefender` |
| **Authentication** | API key, sent in the `apikey` header |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | Yes |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key. Downloading samples is reserved to the partners of OPSWAT's malware exchange program, and the feed requires a license with feed access.

In the [configuration file](../configuration.md):

```ini
[API keys]
metadefender = YOUR-KEY
```

## Command line

```sh
# download a sample with MetaDefender only
malsearch <sha256> --select metadefender -o samples

# download the samples of MetaDefender's feed with MetaDefender only
malsearch -m --select metadefender -o samples

# use every configured client except MetaDefender
malsearch <sha256> --skip metadefender -o samples
```

The feed gives the SHA256 hashes of the infected files of the last 30 days.

## Python

```python
from malsearch import MetaDefender

client = MetaDefender(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256

for h in client.get_malware_feed():
    print(h)
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- The API answers with a download link, from which MalSearch downloads the sample.
- MetaDefender Cloud does not store the files of an archive separately, so the downloaded file may be an archive that contains the sample. MalSearch then extracts the file that matches the hash (trying the password `infected`).
