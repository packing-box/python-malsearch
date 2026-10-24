<p align="center"><img src="https://github.com/packing-box/python-malsearch/raw/main/docs/pages/img/logo.png"></p>
<h1 align="center">MalSearch <a href="https://twitter.com/intent/tweet?text=MalSearch%20-%20Search%20for%20samples%20from%20various%20malware%20databases.%0D%0APython%20library%20for%20getting%20samples%20from%20multiple%20malware databases.%0D%0Ahttps%3a%2f%2fgithub%2ecom%2fpacking-box%2fpython-malsearch%0D%0A&hashtags=python,programming,malware"><img src="https://img.shields.io/badge/Tweet--lightgrey?logo=twitter&style=social" alt="Tweet" height="20"/></a></h1>
<h3 align="center">Search for samples from various malware databases.</h3>

[![PyPi](https://img.shields.io/pypi/v/malsearch.svg)](https://pypi.python.org/pypi/malsearch/)
[![Read The Docs](https://readthedocs.org/projects/python-malsearch/badge/?version=latest)](https://python-malsearch.readthedocs.io/en/latest/?badge=latest)
[![Build Status](https://github.com/packing-box/python-malsearch/actions/workflows/python-package.yml/badge.svg)](https://github.com/packing-box/python-malsearch/actions/workflows/python-package.yml)
[![Coverage Status](https://raw.githubusercontent.com/packing-box/python-malsearch/main/docs/coverage.svg)](#)
[![Python Versions](https://img.shields.io/pypi/pyversions/malsearch.svg)](https://pypi.python.org/pypi/malsearch/)
[![Known Vulnerabilities](https://snyk.io/test/github/packing-box/python-malsearch/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/packing-box/python-malsearch?targetFile=requirements.txt)
[![License](https://img.shields.io/pypi/l/malsearch.svg)](https://pypi.python.org/pypi/malsearch/)

This library communicates with the APIs of the following malware databases to download samples by hash and, for some of them, to get feeds of recent sample hashes:

| Service                                                         | Name in config   | Download by                               | Feed | Notes                                                  |
|:----------------------------------------------------------------|:-----------------|:------------------------------------------|:----:|:-------------------------------------------------------|
| [ANY.RUN](https://any.run/api-documentation/)                   | `anyrun`         | MD5, SHA1, SHA256                         |      | requires a TI Lookup license                           |
| [AndroZoo](https://androzoo.uni.lu/api_doc)                     | `androzoo`       | SHA256                                    |      | Android apps only ; API key granted on request         |
| [Hybrid Analysis](https://hybrid-analysis.com/docs/api/v2)      | `hybridanalysis` | SHA256                                    | ✓    | downloading requires a vetted account                  |
| [Joe Sandbox](https://github.com/joesecurity/jbxapi)            | `joesandbox`     | MD5, SHA1, SHA256                         |      | downloading may require a Cloud Pro account            |
| [Koodous](https://docs.koodous.com/api/apks.html)               | `koodous`        | SHA256                                    |      | Android apps only ; no downloads with the free plan    |
| [Maldatabase](https://maldatabase.com/api-doc.html)             | `maldatabase`    |                                           | ✓    |                                                        |
| [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api)  | `malpedia`       | MD5, SHA256                               |      |                                                        |
| [MalShare](https://malshare.com/doc.php)                        | `malshare`       | MD5, SHA1, SHA256                         |      |                                                        |
| [Malware Bazaar](https://bazaar.abuse.ch/api)                   | `malwarebazaar`  | SHA256                                    |      | at most 2000 downloads per day                         |
| [Malware-Feed](https://github.com/MalwareSamples/Malware-Feed)  | `malwarefeed`    | SHA256                                    | ✓    | uses a GitHub token instead of an API key              |
| [MetaDefender](https://docs.opswat.com/mdcloud)                 | `metadefender`   | MD5, SHA1, SHA256                         | ✓    | downloads for malware exchange partners only           |
| [PolySwarm](https://github.com/polyswarm/polyswarm-api)         | `polyswarm`      | MD5, SHA1, SHA256                         |      |                                                        |
| [SOREL-20M](https://github.com/sophos/SOREL-20M)                | `sorel20m`       | SHA256                                    |      | no API key ; Windows PE only (static dataset, 2020)    |
| [theZoo](https://github.com/ytisf/theZoo)                      | `thezoo`         | MD5, SHA1, SHA256                         | ✓    | no API key ; first use indexes ~420 MB of archives     |
| [Triage](https://tria.ge/docs)                                  | `triage`         | MD5, SHA1, SHA256, SHA512                 |      |                                                        |
| [UnpacMe](https://api.unpac.me)                                 | `unpacme`        | SHA256                                    | ✓    | paid plan ; monthly download limit ; supports `-u`     |
| [URLhaus](https://urlhaus-api.abuse.ch)                         | `urlhaus`        | SHA256                                    | ✓    | same Auth-Key as the other abuse.ch services           |
| [VirusShare](https://virusshare.com/apiv2_reference)            | `virusshare`     | MD5, SHA1, SHA224, SHA256, SHA384, SHA512 |      |                                                        |
| [VirusTotal](https://docs.virustotal.com/reference/overview)    | `virustotal`     | MD5, SHA1, SHA256                         |      | downloading requires a premium API key ; supports `-u` |

A service is only asked for the hash types it supports.


```sh
pip install malsearch
```

## :sunglasses: Usage

### Configuration

MalSearch reads the API keys from an INI configuration file, by default `~/.malsearch.conf`. Each key is set in the `API keys` section under the client's name from the table above; only the clients listed there are used, except a client named with `--select`, which gets a warning if its key is missing. SOREL-20M and theZoo need no key: list them with an empty value (`sorel20m =`, `thezoo =`) to use them.

theZoo only publishes the hashes of its archives, not of the samples inside. On first use, MalSearch downloads every archive listed in theZoo's `maldb.db` (about 420 MB, which takes several minutes) and builds an index of the sample hashes in the user cache directory (`~/.cache/malsearch/thezoo.json` on Linux). Later runs only download the archives that changed.

```ini
[API keys]
androzoo = YOUR-KEY
anyrun = YOUR-KEY
hybridanalysis = YOUR-KEY
joesandbox = YOUR-KEY
koodous = YOUR-TOKEN
maldatabase = YOUR-KEY
malpedia = YOUR-KEY
malshare = YOUR-KEY
malwarebazaar = YOUR-KEY
malwarefeed = YOUR-GITHUB-TOKEN
metadefender = YOUR-KEY
polyswarm = YOUR-KEY
sorel20m = 
thezoo = 
triage = YOUR-KEY
unpacme = YOUR-KEY
urlhaus = YOUR-KEY
virusshare = YOUR-KEY
virustotal = YOUR-KEY
```

When a service hits its rate limit or rejects its API key, MalSearch disables that client for a while. It records this in a `Disabled` section of the same file, with an expiration date (`DD/MM/YYYY HH:MM:SS`), and re-enables the client automatically once that date has passed. You can also add an entry yourself to disable a client temporarily. An entry whose value is not a date disables the client until you remove it.

### Command line

```sh
# download a sample (MD5, SHA1, SHA224, SHA256, SHA384 or SHA512) to the current directory
malsearch 2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9

# only query some clients (or exclude some with --skip) ; put the hashes first, as --select and --skip take all
#  the names that follow them
malsearch 094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d --select malwarebazaar virustotal

# download every hash from a newline-separated list into the "samples" folder, without the requests cache
malsearch -f hashes.txt -o samples --disable-cache

# download the latest samples published by the hash feeds
malsearch -m -o samples
```

| Option                          | Description                                                                           |
|:--------------------------------|:--------------------------------------------------------------------------------------|
| `-f`, `--from-file FILE`        | read hashes from a file (one per line)                                                |
| `-m`, `--from-malware-feed`     | get hashes from the malware feeds                                                     |
| `-c`, `--config FILE`           | INI configuration file (default: `~/.malsearch.conf`)                                 |
| `-o`, `--output-dir DIR`        | output directory for downloaded samples (default: `.`)                                |
| `--select NAME [NAME ...]`      | only use the given clients                                                            |
| `--skip NAME [NAME ...]`        | do not use the given clients                                                          |
| `-u`, `--unpacked`              | also download the unpacked versions of a packed sample (VirusTotal, UnpacMe)          |
| `--disable-cache`               | disable the requests cache (responses are otherwise cached for one day)               |
| `-v`, `--verbose`               | display debug information                                                             |

Each sample is saved under its hash as the filename, and samples that already exist in the output directory are skipped. For each hash, the clients are tried in turn until one returns the sample. Several hashes are downloaded in parallel, with a progress bar if [`tqdm`](https://pypi.org/project/tqdm/) is installed.

### Python

The same features are available from Python. Unlike the command line, the functions below do not create the output directory, so make sure it exists first:

```python
from malsearch import download_samples, get_samples_feed

# download samples, using the same options as on the command line
download_samples("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9",
                 config="~/.malsearch.conf", output_dir="samples", select=["malwarebazaar", "virustotal"])

# iterate over the hashes from the malware feeds
for h in get_samples_feed(config="~/.malsearch.conf"):
    print(h)
```

You can also use a single client directly:

```python
from malsearch import MalwareBazaar

MalwareBazaar(api_key="YOUR-KEY", output_dir="samples").get_file_by_hash("2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9")
```


## :clap:  Supporters

[![Stargazers repo roster for @packing-box/python-malsearch](https://reporoster.com/stars/dark/packing-box/python-malsearch)](https://github.com/packing-box/python-malsearch/stargazers)

[![Forkers repo roster for @packing-box/python-malsearch](https://reporoster.com/forks/dark/packing-box/python-malsearch)](https://github.com/packing-box/python-malsearch/network/members)

<p align="center"><a href="#"><img src="https://img.shields.io/badge/Back%20to%20top--lightgrey?style=social" alt="Back to top" height="20"/></a></p>
