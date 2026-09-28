#!/usr/bin/env python3
"""Compatibility entry point for existing Marzban CLI installations."""
from pathlib import Path
import os
import runpy
import sys

if __name__ == "__main__":
    os.environ.setdefault('CLI_PROG_NAME', Path(sys.argv[0]).name)
    runpy.run_path(str(Path(__file__).with_name('rime-cli.py')), run_name='__main__')
