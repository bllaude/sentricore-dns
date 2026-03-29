#!/usr/bin/env python3
"""
Sentricore DNS Web Dashboard Runner
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

    print("Starting Sentricore DNS Web Dashboard...")

    # Start the web app
    subprocess.run(["venv/bin/python", "app/web/app.py"])

if __name__ == "__main__":
    main()