#!/usr/bin/env bash

VENV=${1:-"venv"}
DB=${2:-"repository.db"}

cd "$(dirname "$0")"
cd ../src/auction_repository
echo -e "Check for auction repository db: $DB"
if [ ! -d $DB ]; then
  echo -e "Create auction repository db"
  sqlite3 $DB <<EOF
create table users (id INTEGER PRIMARY KEY, title TEXT, desc TEXT, type INTEGER, subtype INTEGER, expires INTEGER, limit integer);
EOF
fi
cd ..
echo -e "Activate virtual environment: $VENV"
source $VENV/bin/activate
echo -e "Execute auction repository"
cd ..
python3 -m src.auction_repository.auction_repository
