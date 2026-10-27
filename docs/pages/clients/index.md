# Clients

Each service is handled by a client: a Python class of the `malsearch` package, named in the [configuration file](../configuration.md) by its lowercase name.

| Service | Name in config | Python class | Download by | Feed | `-u` |
|:--|:--|:--|:--|:--:|:--:|
| [AndroZoo](androzoo.md) | `androzoo` | `AndroZoo` | SHA256 | | |
| [ANY.RUN](anyrun.md) | `anyrun` | `AnyRun` | MD5, SHA1, SHA256 | | |
| [Hybrid Analysis](hybridanalysis.md) | `hybridanalysis` | `HybridAnalysis` | SHA256 | ✓ | |
| [Joe Sandbox](joesandbox.md) | `joesandbox` | `JoeSandbox` | MD5, SHA1, SHA256 | | |
| [Koodous](koodous.md) | `koodous` | `Koodous` | SHA256 | | |
| [Maldatabase](maldatabase.md) | `maldatabase` | `Maldatabase` | | ✓ | |
| [Malpedia](malpedia.md) | `malpedia` | `Malpedia` | MD5, SHA256 | | |
| [MalShare](malshare.md) | `malshare` | `MalShare` | MD5, SHA1, SHA256 | ✓ | |
| [Malware Bazaar](malwarebazaar.md) | `malwarebazaar` | `MalwareBazaar` | MD5, SHA1, SHA256 | ✓ | |
| [Malware-Feed](malwarefeed.md) | `malwarefeed` | `MalwareFeed` | SHA256 | ✓ | |
| [MetaDefender](metadefender.md) | `metadefender` | `MetaDefender` | MD5, SHA1, SHA256 | ✓ | |
| [PolySwarm](polyswarm.md) | `polyswarm` | `PolySwarm` | MD5, SHA1, SHA256 | | |
| [SOREL-20M](sorel20m.md) | `sorel20m` | `Sorel20M` | SHA256 | | |
| [theZoo](thezoo.md) | `thezoo` | `TheZoo` | MD5, SHA1, SHA256 | ✓ | |
| [Triage](triage.md) | `triage` | `Triage` | MD5, SHA1, SHA256, SHA512 | | |
| [UnpacMe](unpacme.md) | `unpacme` | `UnpacMe` | SHA256 | ✓ | ✓ |
| [URLhaus](urlhaus.md) | `urlhaus` | `URLhaus` | SHA256 | ✓ | |
| [VirusShare](virusshare.md) | `virusshare` | `VirusShare` | all six | | |
| [VirusTotal](virustotal.md) | `virustotal` | `VirusTotal` | MD5, SHA1, SHA256 | | ✓ |

## About the examples

In the examples of the client pages, replace `<sha256>` (or `<md5>`) with the hash of the sample to download, and `YOUR-KEY` with your API key. On the command line, `--select <name>` restricts MalSearch to that client; without it, every configured client is tried in turn.

All the clients share the same interface from Python:

```python
from malsearch import MalShare

client = MalShare(api_key="YOUR-KEY", output_dir="samples")
client.get_file_by_hash("<sha256>")     # downloads and saves samples/<sha256>
data = client.content                   # the sample, as bytes

for h in client.get_malware_feed():     # only for the clients with a hash feed
    print(h)
```

See the [Python API](../api.md) for the constructor options and the errors raised.
