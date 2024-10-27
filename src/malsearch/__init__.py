# -*- coding: UTF-8 -*-
from .clients import *
from .clients import __all__ as _clients


__all__ = ["download_sample", "download_samples"] + _clients

_CLIENTS_MAP = {n.lower(): globals()[n] for n in _clients}


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


def download_sample(hash, config=None, **kwargs):
    import logging
    logger = logging.getLogger("malsearch")
    if config is None:
        logger.error("no configuration file provided")
        logger.info(f"you can create one at {config} manually (INI format with section 'API keys')")
    else:
        import datetime as dt
        from os.path import exists, join
        p = join(kwargs.get('output_dir', "."), hash)
        if exists(p) and not kwargs.get('overwrite'):
            logger.info(f"'{p}' already exists")
            return
        if isinstance(config, str):
            config = _valid_conf(config)
        clients = []
        for n in config['API keys']:
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
            clients.append(n)
        if len(clients) == 0:
            logger.warning("no download client available/enabled")
        logger.debug(f"clients: {', '.join(clients)}")
        for n in clients:
            logger.debug(f"trying {n}...")
            cls = _CLIENTS_MAP[n]
            if cls.__base__.__name__ == "API":
                kwargs['api_key'] = config['API keys'].get(n)
            client = cls(config=config, **kwargs)
            try:
                client.get_file_by_hash(hash)
                if hasattr(client, "content") and client.content is not None and len(client.content) > 0:
                    logger.debug("found sample !")
                    return
            except ValueError as e:
                logger.debug(e)
            except Exception as e:
                logger.exception(e)
    logger.warning(f"could not find the sample with hash {hash}")


def download_samples(*hashes, max_workers=5, **kwargs):
    from concurrent.futures import ThreadPoolExecutor as Pool
    from threading import Lock
    kwargs['lock'] = Lock()
    with Pool(max_workers=max_workers) as executor:
        for h in hashes:
            executor.submit(download_sample, h.lower(), **kwargs)
