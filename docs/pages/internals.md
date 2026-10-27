# How it works

## Downloading a sample

For each hash, MalSearch:

1. skips the hash if a file with this name already exists in the output directory;
2. tries the configured clients **in the order of the `API keys` section** of the [configuration file](configuration.md), leaving out the clients that are skipped, disabled or cannot download (e.g. [Maldatabase](clients/maldatabase.md));
3. skips the clients that do not support the hash type (e.g. an MD5 hash is not sent to a SHA256-only service);
4. stops at the first client that returns the sample, and saves it under its hash.

If no client returns the sample, MalSearch logs a warning. Several hashes are downloaded in parallel (3 threads per CPU by default).

## Saving a sample

- Many services serve samples in archives, often protected by the password `infected`. MalSearch extracts the file that matches the requested hash, and keeps the downloaded file as is when it already matches (e.g. an APK, which is a ZIP itself).
- The file is created with permissions `600`, readable and writable by its owner only and never executable, including when it overwrites an existing file.
- MalSearch then checks that the saved content matches the hash, and warns if it does not.

## Rate limits and disabled clients

MalSearch disables a client for a while when:

- the service answers `429` (rate limit or quota reached): for the time given in its `Retry-After` header if any, 5 minutes otherwise;
- the service rejects the API key (e.g. `401` or `403`, depending on the service): for 5 minutes.

The client is disabled in memory, so that the downloads in progress stop using it, and in the `Disabled` section of the configuration file, so that the next runs skip it too until the expiration date. See [Configuration](configuration.md#disabled-clients).

Other errors only affect the current hash: a `404` means that the service does not know the sample, and a server error (`5xx`) or a network error makes MalSearch try the next client.

## Requests cache

The command line installs a [`requests-cache`](https://requests-cache.readthedocs.io) cache, in the user cache directory, that only keeps the `404` ("not found") answers, for one day (or as long as the service's `Cache-Control` header says). A hash that a service does not know is therefore not asked to it again for a day, while successful responses, such as the samples themselves, are never cached. When a request fails, a stale cached answer is used if there is one. Disable the cache with `--disable-cache`.

API keys passed as URL parameters (`api_key`, `apikey`) are not stored in the cache.

## API keys in logs

MalSearch never logs the URLs of its requests nor the messages of request exceptions, as they may contain an API key, and the debug messages of `urllib3` are silenced on the command line. When a service rejects a key, MalSearch logs the service's own message (e.g. "Invalid API key") to help you fix it.
