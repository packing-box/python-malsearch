# Python API

MalSearch can be used in two ways from Python: through high-level functions that use your [configuration file](configuration.md), like the command line, or through a single client.

Unlike the command line, the Python API does not create the output directory, so make sure it exists first.

## High-level functions

### `download_samples`

```python
download_samples(*hashes, max_workers=3 * cpu_count(), config=None, **kwargs)
```

Downloads the given samples in parallel, trying the configured clients in turn for each hash.

```python
import os
from malsearch import download_samples

os.makedirs("samples", exist_ok=True)
download_samples("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9",
                 "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d",
                 config="~/.malsearch.conf", output_dir="samples", select=["malwarebazaar", "virustotal"])
```

### `download_sample`

```python
download_sample(hash, config=None, **kwargs)
```

Downloads a single sample. It returns the client that found the sample, whose `content` attribute holds the sample, or `None` if no client found it (or if the sample already exists in the output directory).

```python
from malsearch import download_sample

if (client := download_sample("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9",
                              config="~/.malsearch.conf", output_dir="samples")) is not None:
    print(f"found on {client.name} ({len(client.content)} bytes)")
```

### `get_samples_feed`

```python
get_samples_feed(config=None, **kwargs)
```

Yields the hashes from the feeds of the configured clients that have one.

```python
from malsearch import download_samples, get_samples_feed

hashes = list(get_samples_feed(config="~/.malsearch.conf", skip=["malwarefeed"]))
download_samples(*hashes, config="~/.malsearch.conf", output_dir="samples")
```

### Arguments

| Argument | Description |
|:--|:--|
| `config` | path to the [configuration file](configuration.md) (**required**: without it, MalSearch logs an error and does nothing) |
| `output_dir` | output directory (default: current directory) |
| `select` | list of the names of the clients to use (default: all the configured ones) |
| `skip` | list of the names of the clients not to use |
| `unpacked` | also download the unpacked files of a packed sample ([VirusTotal](clients/virustotal.md), [UnpacMe](clients/unpacme.md)) |
| `overwrite` | download a sample even if it already exists in the output directory (default: `False`) |
| `max_workers` | number of parallel downloads, for `download_samples` only (default: 3 times the number of CPUs) |

The other keyword arguments are passed to the clients (see below).

## Clients

Each client can also be used on its own, without a configuration file. The class names are listed on the [Clients](clients/index.md) page.

```python
from malsearch import MalwareBazaar

client = MalwareBazaar(api_key="YOUR-KEY", output_dir="samples", error=True)
client.get_file_by_hash("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9")
```

### Constructor arguments

| Argument | Description |
|:--|:--|
| `api_key` | API key (or token) of the service; not needed for [SOREL-20M](clients/sorel20m.md) and [theZoo](clients/thezoo.md) |
| `output_dir` | output directory (default: `./`) |
| `unpacked` | also download the unpacked files ([VirusTotal](clients/virustotal.md), [UnpacMe](clients/unpacme.md)) |
| `error` | log decoding, extraction and saving failures as errors instead of debug messages (default: `False`) |
| `postcheck` | warn if the saved content does not match the hash (default: `True`) |

### Methods and attributes

| Name | Description |
|:--|:--|
| `get_file_by_hash(hash)` | download the sample and save it in the output directory, under its hash (all clients but Maldatabase) |
| `get_malware_feed()` | yield hashes from the service's feed (only the clients with a feed) |
| `content` | content of the last download, as bytes |
| `name` | client name, as in the configuration file |
| `url`, `doc` | base URL of the API and link to its documentation |

### Errors

`get_file_by_hash` raises:

- `ValueError` if the service does not support this hash type;
- `HashNotFoundError` if the service does not know the sample;
- `ServiceUnavailable` if the service cannot be reached, answers with a server error, has no API key, or is disabled (rate limit or rejected key).

```python
from malsearch import VirusTotal
from malsearch.clients.__common__ import HashNotFoundError, ServiceUnavailable

client = VirusTotal(api_key="YOUR-KEY", output_dir="samples")
try:
    client.get_file_by_hash("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9")
except HashNotFoundError:
    print("unknown sample")
except ServiceUnavailable as e:
    print(e)
```

The high-level functions catch these errors and try the next client.

## Logging

MalSearch logs through the `malsearch` logger:

```python
import logging

logging.basicConfig(level=logging.INFO)          # which client found each sample, missing samples
logging.getLogger("malsearch").setLevel(logging.DEBUG)   # every attempt
```

## Caching

The command line caches the "not found" answers of the services for one day (see [How it works](internals.md#requests-cache)). The Python API does not: install a cache yourself with [`requests-cache`](https://requests-cache.readthedocs.io) if you need one, for instance the same as the command line:

```python
from requests_cache import install_cache

install_cache("malsearch", use_cache_dir=True, expire_after=86400, allowable_codes=[404],
              allowable_methods=["GET", "POST"], ignored_parameters=["api_key", "apikey"])
```
