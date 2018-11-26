#!/usr/bin/env bash

cd "$(dirname "$0")"
echo -e "Activate virtual environment"
cd ..
source venv/bin/activate
echo -e "Execute auction manager"
cd ..
python3 -m security2018-p1g1.auction_manager.auction_manager
