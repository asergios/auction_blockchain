# coding: utf-8

import sqlite3
import logging
import json
import os
from datetime import datetime, timedelta
from Crypto.Hash import SHA256


logging.basicConfig(level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RDB')
logger.setLevel(logging.DEBUG)


class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)

    def store_auction(self, title, desc, atype, subtype, duration):
        start = datetime.now()
        stop = (start + timedelta(seconds=duration)) if duration > 0 else 0
        cursor = self.db.cursor()
        # Seed para a primeira bid usar na hash (blockchain)
        seed = os.urandom(32).hex()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, duration, start, stop, seed) VALUES(?,?,?,?,?,?,?,?)',
                (title, desc, atype, subtype, duration, start, stop, seed))
        rv = cursor.lastrowid
        self.db.commit()
        return rv

    def list_auctions(self):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM auctions ORDER BY open DESC')
        return cursor.fetchall()

    def get_auctions(self, auction_ids):
        cursor = self.db.cursor()
        placeholder= '?'
        placeholders= ', '.join(placeholder for id in auction_ids)
        query = 'SELECT * FROM auctions WHERE id IN (%s)' % placeholders
        cursor.execute(query, auction_ids)
        return cursor.fetchall()

    def get_bid(self, auction_id, sequence):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM bids WHERE auction_id = ? AND sequence = ?', (auction_id, sequence))
        return cursor.fetchone()

    def get_bids(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM bids WHERE auction_id = ? ORDER BY sequence DESC', (auction_id,))
        return cursor.fetchall()

    def get_last_sequence(self, auction_id):
        ls = -1

        cursor = self.db.cursor()
        cursor.execute('SELECT sequence FROM bids WHERE auction_id = ? ORDER BY sequence DESC', (auction_id,))
        row = cursor.fetchone()

        if row is not None:
            ls = row[0]

        return ls

    def get_last_bid(self, auction_id):
        s = self.get_last_sequence(auction_id)
        if s >= 0:
            return self.get_bid(auction_id, s)
        return None

    def close_auctions(self):
        now = datetime.now()
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM auctions WHERE open = 1 AND duration > 0')
        rows = cursor.fetchall()

        for row in rows:
            if now >= row[7]:
                cursor.execute('UPDATE auctions SET open = 0 WHERE id = ?', (row[0],))
        self.db.commit()

    def close_auction(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('UPDATE auctions SET open = 0 WHERE id = ?', (auction_id,))
        self.db.commit()

    def store_bid(self, auction_id, identity, value):
        ls = self.get_last_sequence(auction_id)

        sequence = 0
        if ls < 0:
            prev_hash = self.get_auctions([auction_id])[0][8]
        else:
            last_bid = self.get_bid(auction_id, ls)
            last_bid_dict = {'PREV_HASH': last_bid[2], 'IDENTITY': last_bid[3],
                    'VALUE': last_bid[4]}
            prev_hash = SHA256.new(data=json.dumps(last_bid_dict).encode("UTF-8")).hexdigest()
            sequence = ls + 1

        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, prev_hash, identity, value) VALUES(?,?,?,?,?)',(auction_id, sequence, prev_hash, identity, value))
        self.db.commit()

        return (prev_hash, sequence)

    def close(self):
        self.db.commit()
        self.db.close()
