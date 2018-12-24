#!/usr/bin/env bash

VENV=${1:-"venv"}
DB=${2:-"mananger.db"}

cd "$(dirname "$0")"
cd ../src/auction_manager
echo -e "Check for auction manager db: $DB"
if [ ! -d $DB ]; then
  echo -e "Create auction mananger db"
  sqlite3 $DB <<EOF
create table users (id INTEGER PRIMARY KEY, cc TEXT);
create table auctions (id_user INTEGER, id_auction INTEGER, PRIMARY KEY (id_user, id_auction))
EOF
fi
cd ..
echo -e "Activate virtual environment: $VENV"
source $VENV/bin/activate
echo -e "Execute auction manager"
cd ..
python3 -m src.auction_manager.auction_manager
