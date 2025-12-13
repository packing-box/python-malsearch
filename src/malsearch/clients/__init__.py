# -*- coding: UTF-8 -*-
import importlib
import os


__all__ = []

DOCSTR = """
>>> from malsearch import {cls}
>>> {cls}(api_key="YOUR-KEY", error=True).get_file_by_hash("HASH")
"""


for f in sorted(os.listdir(os.path.dirname(os.path.abspath(__file__)))):
    if not f.endswith(".py") or f.startswith("_"):
        continue
    for cls in (module := importlib.import_module(f".{f[:-3]}", package=__name__)).__all__:
        __all__.append(cls)
        globals()[cls] = c = getattr(module, cls)
        c.__doc__ = DOCSTR.format(cls=cls)

