# -*- coding: UTF-8 -*-
import logging
from os import cpu_count

from .clients import *
from .clients import __all__ as _clients
from .clients.__common__ import _valid_hash


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
                cmap = {n: cls for n, cls in _CLIENTS_MAP.items() if (s := kwargs.get('select')) is None or n in s}
                clients, skipped = [], kwargs.get('skip') or []
                for n in config['API keys']:
                    if n not in cmap.keys() or not hasattr(cmap[n], method):
                        continue
                    if n in skipped:
                        logger.debug(f"{n} skipped")
                        continue
                    if config.has_section("Disabled"):
                        t = config['Disabled'].get(n)
                        if t is not None:
                            import datetime as dt
                            try:
                                if dt.datetime.strptime(t, "%d/%m/%Y %H:%M:%S") < dt.datetime.now():
                                    from contextlib import nullcontext
                                    with kwargs.get('lock') or nullcontext():
                                        config['Disabled'].pop(n)
                                        with open(config.path, 'w') as cfg:
                                            config.write(cfg)
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


def _valid_hash_file(path):
    from os.path import exists, expanduser
    path = expanduser(path)
    if not exists(path):
        raise ValueError("hashes file does not exist")
    hashes = []
    with open(path) as f:
        for l in f:
            hashes.append(_valid_hash(l.strip()))
    return hashes


@_check_conf("get_file_by_hash")
def download_sample(hash, config=None, **kwargs):
    """ Function to download a single sample """
    from os.path import exists, join
    p = join(kwargs.get('output_dir', "."), hash)
    if exists(p) and not kwargs.get('overwrite'):
        logger.info(f"'{p}' already exists")
        return
    for client in kwargs['clients']:
        logger.debug(f"trying {client.name}...")
        try:
            client.get_file_by_hash(hash)
            if len(getattr(client, "content", "")) > 0:
                logger.info(f"found {hash} on {client.__class__.__name__} !")
                return client
        except AttributeError:
            continue  # not a client for downloading samples (e.g. Maldatabase)
        except (HashNotFoundError, ServiceUnavailable, ValueError) as e:
            logger.debug(e)
        except Exception as e:
            logger.exception(e)
    logger.warning(f"could not find {hash}")


def download_samples(*hashes, max_workers=_MAX_WORKERS, **kwargs):
    """ Threaded function to download samples from hashes in parallel. """
    from concurrent.futures import as_completed, ThreadPoolExecutor as Pool
    from threading import Lock
    try:
        from tqdm import tqdm
        TQDM = True
    except ImportError:
        TQDM = False
    kwargs['lock'] = Lock()
    if len(hashes) == 0:
        return
    elif len(hashes) == 1:
        download_sample(hashes[0].lower(), **kwargs)
    else:
        with Pool(max_workers=max_workers) as executor:
            tasks = []
            for h in hashes:
                tasks.append(executor.submit(download_sample, h.lower(), **kwargs))
            for task in (tqdm(as_completed(tasks), total=len(hashes)) if TQDM else as_completed(tasks)):
                task.result()


@_check_conf("get_malware_feed")
def get_samples_feed(config=None, **kwargs):
    count = 0
    for client in kwargs['clients']:
        logger.debug(f"trying {client.name}...")
        try:
            for h in client.get_malware_feed():
                yield h
                count += 1
        except Exception as e:
            logger.exception(e)
    logger.info(f"got {count} hashes")

