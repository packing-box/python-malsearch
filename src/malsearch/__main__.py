# -*- coding: UTF-8 -*-
from .__info__ import __author__, __copyright__, __email__, __license__, __source__, __version__


def _parser(name, description, examples):
    from argparse import ArgumentParser, RawTextHelpFormatter
    descr = f"{name} {__version__}\n\nAuthor   : {__author__} ({__email__})\nCopyright: {__copyright__}\nLicense  :" \
            f" {__license__}\nSource   : {__source__}\n\n{description}.\n\n"
    return ArgumentParser(description=descr, formatter_class=RawTextHelpFormatter, add_help=False,
                          epilog="usage examples:\n- " + "\n- ".join(examples) if len(examples) > 0 else None)


def _setup(parser):
    args = parser.parse_args()
    if hasattr(args, "verbose"):
        import logging
        logging.basicConfig(level=[logging.INFO, logging.DEBUG][args.verbose])
    if not args.disable_cache:
        from requests_cache import install_cache
        install_cache("malsearch",
            use_cache_dir=True,                 # Save files in the default user cache dir
            cache_control=True,                 # Use Cache-Control response headers for expiration, if available
            expire_after=86400,                 # Otherwise expire responses after one day
            allowable_codes=[404],              # Cache 400 responses as a solemn reminder of your failures
            allowable_methods=['GET', 'POST'],  # Cache whatever HTTP methods you want
            ignored_parameters=['api_key'],     # Don't match this request param, and redact if from the cache
            match_headers=['Accept-Language'],  # Cache a different response per language
            stale_if_error=True,                # In case of request errors, use stale cache data if possible
        )
    return args


def main():
    from os import makedirs
    from .__init__ import _valid_conf, download_samples, get_samples_feed
    from .clients.__common__ import _valid_hash
    parser = _parser("MalSearch", "This tool is aimed to search for malware samples across some public databases",
                     ["2037f9b7dd268eef7d2e950b27c6cf80e3ba692d262c785ab67b04dc71c99bf9",
                      "-f hashes.txt -o samples --disable-cache"])
    parser.add_argument("sample_hash", type=_valid_hash, nargs="*", help="input hash")
    parser.add_argument("-f", "--from-file", help="get hashes from the target file (newline-separated list)")
    parser.add_argument("-m", "--from-malware-feed", action="store_true", help="get hashes from malware feeds")
    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-c", "--config", default="~/.malsearch.conf", type=_valid_conf, help="INI configuration file")
    opt.add_argument("-o", "--output-dir", default=".", help="output directory for downloaded samples")
    opt.add_argument("-s", "--skip", nargs="*", help="skip the specified clients while downloading samples")
    opt.add_argument("-u", "--unpacked", action="store_true",
                     help="if available and target sample is packed, download unpacked version too")
    opt.add_argument("--disable-cache", action="store_true", help="disable requests cache")
    extra = parser.add_argument_group("extra arguments")
    extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
    extra.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
    args = _setup(parser)
    if args.from_file is not None:
        with open(args.from_file) as f:
            for h in f.readlines():
                args.sample_hash.append(_valid_hash(h.strip()))
    if args.from_malware_feed:
        for h in get_samples_feed():
            args.sample_hash.append(_valid_hash(h.strip()))
    makedirs(args.output_dir, exist_ok=True)
    if len(args.sample_hash) > 0:
        download_samples(*args.sample_hash, **vars(args))
    else:
        import logging
        logging.getLogger("malsearch").warning("nothing to download")
