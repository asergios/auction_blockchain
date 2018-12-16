#!/usr/bin/env bash

VENV=${1:-venv}

cd "$(dirname "$0")"
cd ../src
echo -e "Activate virtual environment: $VENV"
source venv/bin/activate
echo -e "Execute auction manager"
cd ..
python3 -m src.auction_manager.auction_manager
