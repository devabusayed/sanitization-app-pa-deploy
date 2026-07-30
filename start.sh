#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
  echo "Python 3 is required. Install from https://www.python.org/downloads/"
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate
pip3 install -q -r requirements.txt

python3 main.py --serve
