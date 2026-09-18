#!/usr/bin/env python3
"""Android 10/Termux: package grid and local Roblox session import/export.

Standard library only. Run with Termux Python; grant su when requested.
Session stores vary by APK. Only recognized, existing plaintext cookie stores
are modified. Never create an invented preference key or claim UI login success.
"""

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie

GAP = 8
MIN_CELL = 100
LAUNCH_DELAY = 0.7
WINDOWING_MODE_FREEFORM = 5
BASE = Path(__file__).resolve().parent
CONFIG = BASE / "grid_packages.json"
COOKIE_NAME = ".ROBLOSECURITY"
AUTH_URL = "https://users.roblox.com/v1/users/authenticated"
PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+")
MAX_FILE = 8 * 1024 * 1024


class ToolError(Exception):
    """Safe user-facing message: never embed cookie content."""


def package_ok(value):
    return bool(PACKAGE_RE.fullmatch(value))


def run(cmd, root=False, timeout=20, input_text=None):
    command = shlex.join(cmd) if isinstance(cmd, list) else cmd
    args = ["su", "-c", command] if root else (
        cmd if isinstance(cmd, list) else ["sh", "-c", cmd])
    try:
        p = subprocess.run(args, input=input_text, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ToolError("Lệnh Android quá thời gian; hãy thử lại.") from None
    except OSError:
        raise ToolError("Không chạy được lệnh. Tool cần Python trong Termux và su.") from None
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def android(cmd, timeout=20):
    rc, out, err = run(cmd, root=True, timeout=timeout)
