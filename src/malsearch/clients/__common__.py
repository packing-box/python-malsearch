# -*- coding: UTF-8 -*-
import builtins
import logging


__all__ = ["API", "Web"]

_HASHTYPES_MAP = {'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64, 'sha384': 96, 'sha512': 128}
_MIN_BACKOFF = 300

logger = logging.getLogger("malsearch")


def _hash_type(hash, *types):
    try:
        return {v: k for k, v in _HASHTYPES_MAP.items()}[len(_valid_hash(hash))]
    except ValueError:
        pass


def _valid_hash(hash, *types):
    import re
    pattern = "|".join(f"[0-9a-f]{{{_HASHTYPES_MAP[t]}}}" for t in (types or _HASHTYPES_MAP.keys()))
    if re.match(r"{}".format(f"^{pattern}$"), hash, re.I) is None:
        raise ValueError("hash type not supported")
    return hash.lower()


def hashtype(*types):
    def _wrapper(f):
        from functools import wraps
        @wraps(f)
        def _subwrapper(*args, **kwargs):
            _valid_hash(args[0] if isinstance(args[0], str) else args[1], *types)
            if not isinstance(args[0], str):
                args[0].hash = args[1]
            return f(*args, **kwargs)
        return _subwrapper
    return _wrapper


class HashNotFoundError(Exception):
    __module__ = 'builtins'
    
    def __init__(self, hash, name):            
        super().__init__(f"{hash} is not known to {name}")
builtins.HashNotFoundError = HashNotFoundError


class ServiceUnavailable(Exception):
    __module__ = 'builtins'
    
    def __init__(self, name, reason=None):            
        super().__init__(f"{name} seems to be currently unavailable{[f' ({reason})', ''][reason is None]}")
builtins.ServiceUnavailable = ServiceUnavailable


class _Base:
    def __init__(self, **kwargs):
        self.name = self.__class__.__name__.lower()
        self._error = False
        self._output_dir = "./"
        self._postcheck = True
        for k, v in kwargs.items():
            setattr(self, f"_{k}", v)
    
    def _decode(self, codec):
        try:
            import codext as codecs
        except ImportError:
            import codecs
        try:
            self.content = self.content.encode()
        except:
            pass
        try:
            self.content = codecs.decode(self.content, codec)
        except ValueError as e:
            [logger.debug, logger.error][self._error](f"cannot decode ({e})")
        except Exception as e:
            logger.exception(e)
        return self
    
    def _save(self, filename=None):
        from os.path import join
        try:
            c = self.content
            with open(join(self._output_dir, filename or self.hash), 'wb') as f:
                f.write(c)
            if filename is None and self._postcheck:
                import hashlib
                h = getattr(hashlib, _hash_type(self.hash))()
                h.update(self.content)
                if (hd := h.hexdigest()) != self.hash:
                    logger.warning(f"content and hash mismatch ({hd} != {self.hash})")
        except AttributeError:
            if self.enabled:
                [logger.debug, logger.error][self._error]("cannot save (no content downloaded)")
        except Exception as e:
            logger.exception(e)
        return self
    
    def _unzip(self, password=None):
        from io import BytesIO
        try:
            with BytesIO(self.content) as buffer:
                from pyzipper import AESZipFile
                from zipfile import ZipFile
                for ZipClass in [ZipFile, AESZipFile]:
                    try:
                        with ZipClass(buffer) as zip_file:
                            if password:
                                zip_file.setpassword(password)
                            with zip_file.open(zip_file.namelist()[0]) as file:
                                self.content = file.read()
                                logger.debug("unzipped with {ZipClass}")
                                break
                    except NotImplementedError:
                        continue
        except AttributeError:
            if self.enabled:
                [logger.debug, logger.error][self._error]("cannot unzip (no content downloaded)")
        except Exception as e:
            logger.exception(e)
        return self
    
    @property
    def enabled(self):
        return not hasattr(self, "_config") or \
               not self._config.has_section("Disabled") or \
               self.name not in self._config['Disabled']


class API(_Base):
    def __request(self, path, **kwargs):
        from requests import exceptions, get, post
        if not getattr(self, "_pre_condition", lambda: True)():
            raise HashNotFoundError(self.hash, self.__class__.__name__)
        for i in ["headers", "params"]:
            for k, v in getattr(self, f"_{i}", {}).items():
                kwargs[i] = kwargs[i] or {}
                kwargs[i].setdefault(k, v)
            if n := getattr(self, f"_api_key_{i.rstrip('s')}", None):
                d = kwargs.pop(i, {}) or {}
                d[n] = self._api_key
                kwargs[i] = d
        if n := getattr(self, "_auth_method", None):
            kwargs['headers'] = kwargs['headers'] or {}
            kwargs['headers']['Authorization'] = f"{n} {self._api_key}"
        r = (get if 'params' in kwargs else post)(f"{self.url}/{path}", **kwargs)
        try:
            r.raise_for_status()
            self.content = r.content
        except exceptions.RequestException as e:
            if r.status_code == 403:
                import datetime as dt
                from contextlib import nullcontext
                if hasattr(self, "_config"):
                    with kwargs.get('lock') or nullcontext():
                        if not self._config.has_section("Disabled"):
                            self._config.add_section("Disabled")
                        boff = dt.timedelta(seconds=getattr(self, "backoff", _MIN_BACKOFF))
                        self._config['Disabled'][self.name] = dt.datetime.strftime(dt.datetime.now() + boff,
                                                                                   "%d/%m/%Y %H:%M:%S")
                        with open(self._config.path, 'w') as f:
                            self._config.write(f)
                    logger.warning(f"{self.name} raised 403 (Forbidden) and was disabled ; check out your API key")
            elif r.status_code == 404:
                raise HashNotFoundError(self.hash, self.__class__.__name__)
            elif 500 <= r.status_code < 600:
                raise ServiceUnavailable(self.__class__.__name__, f"{r.status_code} - {r.reason}")
            else:
                logger.exception(e)
        try:
            self.json = r.json()
            if 'content' in self.json.keys():
                self.content = self.json['content']
        except:
            pass
        if not getattr(self, "_post_condition", lambda: True)():
            raise HashNotFoundError(self.hash, self.__class__.__name__)

    def _get(self, path, params=None, headers=None):
        """ Perform a GET request.
        
        :param path:    API endpoint (relative path).
        :param params:  Dictionary of URL parameters.
        :param headers: Optional dictionary of request headers.
        :return:        JSON data or error message.
        """
        self.__request(path, params=params, headers=headers)
        return self
    
    def _post(self, path, data=None, json=None, headers=None):
        """ Perform a POST request.

        :param path:    API endpoint (relative path).
        :param data:    Dictionary or list of tuples for form-encoded data.
        :param json:    Dictionary to send JSON data.
        :param headers: Optional dictionary of request headers.
        :return:        JSON data or error message.
        """
        self.__request(path, data=data, json=json, headers=headers)
        return self


class Web(_Base):
    def _get(self, path, params=None, headers=None):
        """ Perform a GET request.
        
        :param path:    API endpoint (relative path).
        :param params:  Dictionary of URL parameters.
        :param headers: Optional dictionary of request headers.
        :return:        BeautifulSoup-parsed HTML object or None.
        """
        from bs4 import BeautifulSoup
        from requests import exceptions, get
        try:
            r = get(path, params=params, headers=headers)
            r.raise_for_status()
            return BeautifulSoup(r.content, "html.parser")
        except exceptions.RequestException as e:
            return

