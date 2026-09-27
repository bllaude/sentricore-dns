#!/usr/bin/env python3
"""Sentricore DNS Web Dashboard Runner (local dev)."""

import sys

from app.web.app import main

if __name__ == "__main__":
    sys.exit(main())