#!/usr/bin/env python3
"""
Sentricore DNS Proxy Runner
"""

import subprocess
import sys
import os

def main():
    # Change to the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # Set PYTHONPATH to include the project root
    os.environ['PYTHONPATH'] = script_dir

    print("Starting Sentricore DNS Proxy...")

    # Start the DNS proxy in background
    proxy_process = subprocess.Popen(["venv/bin/python", "app/dns/proxy.py"])

    print("DNS Proxy started on port 5300")

    try:
        # Keep running
        proxy_process.wait()
    except KeyboardInterrupt:
        print("\nStopping DNS Proxy...")
        proxy_process.terminate()
        proxy_process.wait()

if __name__ == "__main__":
    main()