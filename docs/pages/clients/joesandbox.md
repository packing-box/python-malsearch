# Joe Sandbox

Joe Sandbox is a malware analysis platform. MalSearch uses the Joe Sandbox Cloud API.

| | |
|:--|:--|
| **Website** | [www.joesandbox.com](https://www.joesandbox.com) |
| **API documentation** | [github.com/joesecurity/jbxapi](https://github.com/joesecurity/jbxapi) |
| **Name in configuration** | `joesandbox` |
| **Python class** | `malsearch.JoeSandbox` |
| **Authentication** | API key, sent in the form data of every (POST) request |
| **Download by** | MD5, SHA1, SHA256 |
| **Hash feed** | No |
| **Unpacked files (`-u`)** | No |

## Requirements

An API key for Joe Sandbox Cloud. Downloading samples may require a **Cloud Pro** account.

In the [configuration file](../configuration.md):

```ini
[API keys]
joesandbox = YOUR-KEY
```

## Command line

```sh
# download a sample with Joe Sandbox only
malsearch <sha256> --select joesandbox -o samples

# use every configured client except Joe Sandbox
malsearch <sha256> --skip joesandbox -o samples
```

## Python

```python
from malsearch import JoeSandbox

client = JoeSandbox(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")    # saved as samples/<sha256>
# accepted hash types: MD5, SHA1, SHA256
```

The output directory must exist. See the [Python API](../api.md) for the other options and the errors raised.

## Notes

- The search also matches filenames, comments, URLs and so on, so MalSearch only keeps the analyses of the exact sample, then downloads the sample of the first one.
- A sample that comes in a ZIP archive is extracted with the password `infected`, unless the downloaded file already matches the hash (e.g. an APK).
