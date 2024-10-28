# -*- coding: UTF-8 -*-
import logging
from os import cpu_count

from .clients import *
from .clients import __all__ as _clients


__all__ = ["download_sample", "download_samples", "get_samples_feed"] + _clients

_CLIENTS_MAP = {n.lower(): globals()[n] for n in _clients}
_MAX_WORKERS = 3 * cpu_count()

logger = logging.getLogger("malsearch")


def _check_conf(method):
    def _wrapper(f):
        from functools import wraps
        @wraps(f)
        def _subwrapper(*args, config=None, **kwargs):
            if config is None:
                logger.error("no configuration file provided")
                logger.info(f"you can create one at {config} manually (INI format with section 'API keys')")
            else:
                if isinstance(config, str):
                    config = _valid_conf(config)
                clients = []
                for n in config['API keys']:
                    if not hasattr(_CLIENTS_MAP[n], method):
                        continue
                    if n in (kwargs.get('skip') or []):
                        logger.debug(f"{n} skipped")
                        continue
                    if config.has_section("Disabled"):
                        t = config['Disabled'].get(n)
                        if t is not None:
                            try:
                                if dt.datetime.strptime(t, "%d/%m/%Y %H:%M:%S") < dt.datetime.now():
                                    from contextlib import nullcontext
                                    with kwargs.get('lock') or nullcontext():
                                        config['Disabled'].pop(n)
                                        with open(config.path, 'w') as f:
                                            config.write(f)
                                else:
                                    logger.warning(f"{n} is disabled until {t}")
                                    continue
                            except ValueError:
                                logger.warning(f"{n} is disabled")
                                continue
                    cls = _CLIENTS_MAP[n]
                    if cls.__base__.__name__ == "API":
                        kwargs['api_key'] = config['API keys'].get(n)
                    clients.append(cls(config=config, **kwargs))
                if len(clients) == 0:
                    logger.warning("no download client available/enabled")
                logger.debug(f"clients: {', '.join(c.name for c in clients)}")
                return f(*args, clients=clients, config=config, **kwargs)
        return _subwrapper
    return _wrapper


def _valid_conf(path):
    from configparser import ConfigParser
    from os.path import exists, expanduser
    path = expanduser(path)
    if not exists(path):
        raise ValueError("configuration file does not exist")
    conf = ConfigParser()
    try:
        conf.read(path)
        conf.path = path
    except:
        raise ValueError("invalid configuration file")
    return conf


@_check_conf("get_file_by_hash")
def download_sample(hash, config=None, **kwargs):
    import datetime as dt
    from os.path import exists, join
    p = join(kwargs.get('output_dir', "."), hash)
    if exists(p) and not kwargs.get('overwrite'):
        logger.info(f"'{p}' already exists")
        return
    for client in clients:
        logger.debug(f"trying {client.name}...")
        try:
            client.get_file_by_hash(hash)
            if hasattr(client, "content") and client.content is not None and len(client.content) > 0:
                logger.debug("found sample !")
                return
        except AttributeError:
            continue  # not a client for downloading samples (e.g. Maldatabase)
        except ValueError as e:
            logger.debug(e)
        except Exception as e:
            logger.exception(e)
    logger.warning(f"could not find the sample with hash {hash}")


def download_samples(*hashes, max_workers=_MAX_WORKERS, **kwargs):
    from concurrent.futures import ThreadPoolExecutor as Pool
    from threading import Lock
    kwargs['lock'] = Lock()
    with Pool(max_workers=max_workers) as executor:
        for h in hashes:
            executor.submit(download_sample, h.lower(), **kwargs)


@_check_conf("get_malware_feed")
def get_samples_feed(config=None, **kwargs):
    count = 0
    for client in clients:
        logger.debug(f"trying {client.name}...")
        try:
            for h in client.get_malware_feed():
                yield h
                count += 1
        except Exception as e:
            logger.exception(e)
    logger.info(f"got {count} hashes")
