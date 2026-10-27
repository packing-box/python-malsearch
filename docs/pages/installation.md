# Installation

MalSearch requires Python 3.10 or later. It is available on [PyPI](https://pypi.org/project/malsearch/):

```sh
pip install malsearch
```

This installs the `malsearch` command and the `malsearch` Python package.

## Optional dependencies

| Package | Used for |
|:--|:--|
| [`tqdm`](https://pypi.org/project/tqdm/) | a progress bar when downloading several samples |
| [`codext`](https://pypi.org/project/codext/) | decoding the content served by [Malware-Feed](clients/malwarefeed.md) (Python's `codecs` is used otherwise) |

```sh
pip install malsearch tqdm
pip install malsearch[codext]
```

## From source

```sh
git clone https://github.com/packing-box/python-malsearch
cd python-malsearch
pip install .
```

Next, [configure](configuration.md) your API keys.
