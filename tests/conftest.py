"""
Make the application modules importable as top-level packages
(database, managers, security, ui), the same way main.py imports them.
"""

import os
import sys

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
