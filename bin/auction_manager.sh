#!/usr/bin/env bash

VENV=${1:-"venv"}
DB=${2:-"manager.db"}

cd "$(dirname "$0")"
echo -e "Check for auction manager db: $DB"
cd ../src/auction_manager
if [ ! -f $DB ]; then
  echo -e "Create auction manager db"
  sqlite3 $DB <<EOF
CREATE TABLE auctions(cc TEXT, auction_id INTEGER, PRIMARY KEY (cc, auction_id));
EOF
fi

echo -e "Activate virtual environment: $VENV"
cd ..
source $VENV/bin/activate

echo -e "Execute auction manager"
cd ..
python3 -m src.auction_manager.auction_manager
