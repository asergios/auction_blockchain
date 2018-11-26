#!/usr/bin/env bash

cd "$(dirname "$0")"
echo -e "Activate virtual environment"
cd ..
source venv/bin/activate
echo -e "Execute auction repository"
cd ..
python3 security2018-p1g1.auction_repository.auction_repository
