#!/usr/bin/env bash

cd "$(dirname "$0")"
echo -e "Activate virtual environment"
cd ..
source venv/bin/activate
echo -e "Execute client"
cd ..
python3 -m security2018-p1g1.client.client security2018-p1g1/client/config.ini
