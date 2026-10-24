## Introduction

MalSearch is a library that allows to collect malware samples from multiple malware databases using their API's. It relies on:

- [AndroZoo](https://androzoo.uni.lu/api_doc)
- [ANY.RUN](https://any.run/api-documentation/)
- [Hybrid Analysis](https://hybrid-analysis.com/docs/api/v2)
- [Joe Sandbox](https://github.com/joesecurity/jbxapi)
- [Koodous](https://docs.koodous.com/api/apks.html)
- [Maldatabase](https://maldatabase.com/api-doc.html) (hash feed only)
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/usage/api)
- [MalShare](https://malshare.com/doc.php)
- [Malware Bazaar](https://bazaar.abuse.ch/api)
- [Malware-Feed](https://github.com/MalwareSamples/Malware-Feed)
- [PolySwarm](https://github.com/polyswarm/polyswarm-api)
- [Triage](https://tria.ge/docs)
- [UnpacMe](https://api.unpac.me)
- [URLhaus](https://urlhaus-api.abuse.ch)
- [VirusShare](https://virusshare.com/apiv2_reference)
- [VirusTotal](https://docs.virustotal.com/reference/overview)

Some of these services require a specific (sometimes paid) account to download samples. See the [README](https://github.com/packing-box/python-malsearch#readme) for the supported hash types, the hash feeds and the requirements of each service.


## Setup

This library is available on [PyPi](https://pypi.python.org/pypi/malsearch/) and can be simply installed using Pip:

```sh
pip install malsearch
```

