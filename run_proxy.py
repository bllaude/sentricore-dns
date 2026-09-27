#!/usr/bin/env python3
"""Sentricore DNS Proxy Runner."""

import sys

from app.dns.proxy import main

if __name__ == "__main__":
    sys.exit(main())
