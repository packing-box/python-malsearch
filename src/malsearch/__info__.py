# -*- coding: UTF-8 -*-
"""MalSearch package information.

"""
import os

__author__    = "Alexandre D'Hondt"
__copyright__ = "© 2024 A. D'Hondt"
__email__     = "alexandre.dhondt@gmail.com"
__license__   = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.fr.html)"
__source__    = "https://github.com/packing-box/malsearch"

with open(os.path.join(os.path.dirname(__file__), "VERSION.txt")) as f:
    __version__ = f.read().strip()

