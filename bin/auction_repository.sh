#!/usr/bin/env bash

VENV=${1:-"venv"}
DB=${2:-"repository.db"}

cd "$(dirname "$0")"
echo -e "Check for auction repository db: $DB"
cd ../src/auction_repository
if [ ! -f $DB ]; then
  echo -e "Create auction repository db"
  sqlite3 $DB <<EOF
CREATE TABLE auctions (id INTEGER PRIMARY KEY, title TEXT, desc TEXT, type INTEGER,
subtype INTEGER, duration INTEGER, start DATETIME, stop DATETIME, blimit INTEGER, open INTEGER DEFAULT 1);
CREATE TABLE bids (auction_id INTEGER, sequence INTEGER, hash TEXT, PRIMARY KEY (auction_id, sequence))
EOF
fi

echo -e "Activate virtual environment: $VENV"
cd ..
source $VENV/bin/activate

echo -e "Execute auction repository"
cd ..
python3 -m src.auction_repository.auction_repository
