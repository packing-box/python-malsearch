# MalSearch

MalSearch is a Python library and command-line tool that downloads malware samples by hash from multiple malware databases, through their APIs. For each hash, it tries the configured services in turn until one of them returns the sample. Some services also provide a feed of recent sample hashes, which MalSearch can download in one go.

```sh
$ pip install malsearch
$ malsearch 2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9 -o samples
```

## Supported services

| Service | Name in config | Download by | Feed | Notes |
|:--|:--|:--|:--:|:--|
| [AndroZoo](clients/androzoo.md) | `androzoo` | SHA256 | | Android apps only ; API key granted on request |
| [ANY.RUN](clients/anyrun.md) | `anyrun` | MD5, SHA1, SHA256 | | requires a TI Lookup license |
| [Hybrid Analysis](clients/hybridanalysis.md) | `hybridanalysis` | SHA256 | ✓ | downloading requires a vetted account |
| [Joe Sandbox](clients/joesandbox.md) | `joesandbox` | MD5, SHA1, SHA256 | | downloading may require a Cloud Pro account |
| [Koodous](clients/koodous.md) | `koodous` | SHA256 | | Android apps only ; no downloads with the free plan |
| [Maldatabase](clients/maldatabase.md) | `maldatabase` | | ✓ | hash feed only |
| [Malpedia](clients/malpedia.md) | `malpedia` | MD5, SHA256 | | |
| [MalShare](clients/malshare.md) | `malshare` | MD5, SHA1, SHA256 | ✓ | |
| [Malware Bazaar](clients/malwarebazaar.md) | `malwarebazaar` | MD5, SHA1, SHA256 | ✓ | at most 2000 downloads per day |
| [Malware-Feed](clients/malwarefeed.md) | `malwarefeed` | SHA256 | ✓ | uses a GitHub token instead of an API key |
| [MetaDefender](clients/metadefender.md) | `metadefender` | MD5, SHA1, SHA256 | ✓ | downloads for malware exchange partners only |
| [PolySwarm](clients/polyswarm.md) | `polyswarm` | MD5, SHA1, SHA256 | | |
| [SOREL-20M](clients/sorel20m.md) | `sorel20m` | SHA256 | | no API key ; Windows PE only (static dataset, 2020) |
| [theZoo](clients/thezoo.md) | `thezoo` | MD5, SHA1, SHA256 | ✓ | no API key ; first use indexes ~420 MB of archives |
| [Triage](clients/triage.md) | `triage` | MD5, SHA1, SHA256, SHA512 | | |
| [UnpacMe](clients/unpacme.md) | `unpacme` | SHA256 | ✓ | paid plan ; monthly download limit ; supports `-u` |
| [URLhaus](clients/urlhaus.md) | `urlhaus` | SHA256 | ✓ | same Auth-Key as Malware Bazaar |
| [VirusShare](clients/virusshare.md) | `virusshare` | MD5, SHA1, SHA224, SHA256, SHA384, SHA512 | | |
| [VirusTotal](clients/virustotal.md) | `virustotal` | MD5, SHA1, SHA256 | | downloading requires a premium API key ; supports `-u` |

A service is only asked for the hash types it supports. Some services require a specific, sometimes paid, account to download samples: see each client's page.

## Where to go next

- [Installation](installation.md) and [Configuration](configuration.md): install MalSearch and set up your API keys.
- [Command line](cli/malsearch.md): download samples with the `malsearch` tool.
- [Clients](clients/index.md): requirements and usage examples for each service.
- [Python API](api.md): use MalSearch from your own code.
- [How it works](internals.md): client selection, rate limits, caching and how samples are saved.

!!! warning "Handle with care"

    The downloaded files are **live malware**. MalSearch saves them readable and writable by their owner only (permissions `600`), never executable, but you should still only handle them in an isolated environment.
