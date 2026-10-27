# `malsearch`

`malsearch` downloads samples by hash, from the command line arguments, from a file or from the hash feeds of the services.

```sh
malsearch [sample_hash ...] [-f FILE] [-m] [-c CONFIG] [-o DIR] [--select NAME ... | --skip NAME ...] [-u] [--disable-cache] [-v]
```

## Options

| Option | Description |
|:--|:--|
| `sample_hash` | hashes to download (MD5, SHA1, SHA224, SHA256, SHA384 or SHA512) |
| `-f`, `--from-file FILE` | read hashes from a file (one per line) |
| `-m`, `--from-malware-feed` | get hashes from the hash feeds of the services |
| `-c`, `--config FILE` | INI [configuration file](../configuration.md) (default: `~/.malsearch.conf`) |
| `-o`, `--output-dir DIR` | output directory for downloaded samples, created if needed (default: `.`) |
| `--select NAME [NAME ...]` | only use the given clients |
| `--skip NAME [NAME ...]` | do not use the given clients |
| `-u`, `--unpacked` | also download the unpacked versions of a packed sample ([VirusTotal](../clients/virustotal.md), [UnpacMe](../clients/unpacme.md)) |
| `--disable-cache` | disable the requests cache ("not found" answers are otherwise cached for one day) |
| `-v`, `--verbose` | display debug information |
| `-h`, `--help` | show the help message and exit |

The hashes from the arguments, from `-f` and from `-m` are combined. `--select` and `--skip` cannot be used together, and they take all the names that follow them: put the hashes **before** them.

## Examples

Download a sample to the current directory:

```sh
malsearch 2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9
```

Download it to the `samples` folder, only querying Malware Bazaar and VirusTotal:

```sh
malsearch 2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9 -o samples --select malwarebazaar virustotal
```

Download every hash of a list (one per line), without the requests cache:

```sh
malsearch -f hashes.txt -o samples --disable-cache
```

Download the latest samples published by the hash feeds of all the configured services:

```sh
malsearch -m -o samples
```

`--select` and `--skip` apply to both the feeds and the downloads. For instance, this only takes the hashes of the MalShare feed and only downloads them from MalShare:

```sh
malsearch -m -o samples --select malshare
```

Download a packed sample and its unpacked files from VirusTotal:

```sh
malsearch 094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d -u -o samples --select virustotal
```

Use another configuration file and show what happens:

```sh
malsearch -f hashes.txt -c ~/work/malsearch.conf -o samples -v
```

See each [client's page](../clients/index.md) for more examples.

## Output

- Each sample is saved under its hash as the filename (lowercase), with permissions `600`.
- A sample that already exists in the output directory is skipped.
- Several hashes are downloaded in parallel, with a progress bar if [`tqdm`](https://pypi.org/project/tqdm/) is installed.
- MalSearch logs which service returned each sample, and warns about the hashes that no service could provide.
