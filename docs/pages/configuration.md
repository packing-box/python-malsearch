# Configuration

MalSearch reads the API keys from an INI configuration file, by default `~/.malsearch.conf`. Use another file with `-c` (`--config`) on the command line, or the `config` argument from [Python](api.md).

## API keys

Each key is set in the `API keys` section, under the client's name in configuration (see [Clients](clients/index.md)):

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

- Only the clients listed in this section are used. Leave out the services you have no account for.
- [SOREL-20M](clients/sorel20m.md) and [theZoo](clients/thezoo.md) need no key: list them with an empty value to use them.
- The clients are tried **in the order of this section**, so put first the services you want to query first (e.g. those with the highest limits).
- A client named with `--select` but missing from this section is still tried, and MalSearch warns that its API key is missing.

Keep this file private: it holds your API keys.

```sh
chmod 600 ~/.malsearch.conf
```

## Disabled clients

When a service hits its rate limit or rejects its API key, MalSearch disables that client for a while. It records this in a `Disabled` section of the same file, with an expiration date (`DD/MM/YYYY HH:MM:SS`), and re-enables the client automatically once that date has passed:

```ini
[Disabled]
virustotal = 27/10/2026 14:05:00
```

You can also add an entry yourself to disable a client temporarily. An entry whose value is not a date disables the client until you remove it:

```ini
[Disabled]
malwarefeed = off
```

See [How it works](internals.md#rate-limits-and-disabled-clients) for when a client gets disabled.
