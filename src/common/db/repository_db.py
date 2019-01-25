# coding: utf-8

import sqlite3
import logging
import json
import os
from datetime import datetime, timedelta
from Crypto.Hash import SHA256
from ..certmanager import CertManager


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ADB')
logger.setLevel(logging.DEBUG)


class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path)

    def store_auction(self, title, desc, atype, subtype, whohides, duration):
        start = datetime.now()
        stop = (start + timedelta(hours=duration)).timestamp() if duration > 0 else 0
        cursor = self.db.cursor()
        # Seed para a primeira bid usar na hash (blockchain)
        seed = os.urandom(32).hex()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, who_hides, duration, start, stop, seed) VALUES(?,?,?,?,?,?,?,?,?)',
                (title, desc, atype, subtype, whohides, duration, start, stop, seed))
        rv = cursor.lastrowid
        self.db.commit()
        return rv

    # Not being used, just here as backup
    '''
    def list_english(self, auction_id=None):
        cursor = self.db.cursor()
        if auction_id is None:
            cursor.execute('SELECT * FROM auctions WHERE type=1 AND open=1')
        else:
            cursor.execute('SELECT * FROM auctions WHERE type=1 AND open=1 AND id=?', (auction_id,))
        return cursor.fetchall()

    def list_blind(self, auction_id=None):
        cursor = self.db.cursor()
        if auction_id is None:
            cursor.execute('SELECT * FROM auctions WHERE type=2 AND open=1')
        else:
            cursor.execute('SELECT * FROM auctions WHERE type=2 AND open=1 AND id=?', (auction_id,))
        return cursor.fetchall()
    '''

    def list_global(self, auction_id):
        cursor = self.db.cursor()
        if not auction_id is None:
            placeholder= '?'
            placeholders= ', '.join(placeholder for id in auction_id)
            query= 'SELECT * FROM auctions WHERE id IN (%s)' % placeholders
            cursor.execute(query, auction_id)
        else:
            query= 'SELECT * FROM auctions'
            cursor.execute(query)
        return cursor.fetchall()

    def get_auction(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM auctions WHERE open=1 AND id=?', (auction_id,))
        return cursor.fetchone()

    def get_last_bid(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM bids WHERE auction_id=? ORDER BY sequence DESC', (auction_id,))
        return cursor.fetchone()

    def get_bids(self, auction_id):
        cursor = self.db.cursor()
        cursor.execute('SELECT * FROM bids WHERE auction_id=? ORDER BY sequence DESC', (auction_id,))
        return cursor.fetchall()

    def last_sequence(self, auction_id):
        ls = -1

        cursor = self.db.cursor()
        cursor.execute('SELECT sequence FROM bids WHERE auction_id=? ORDER BY sequence DESC', (auction_id,))
        rows = cursor.fetchall()

        if len(rows) > 0:
            ls = rows[0][0]

        return ls

    def store_bid(self, auction_id, identity, value):
        last_bid = self.get_last_bid(auction_id)

        # se nao existe uma bid anterior
        if not last_bid:
            prev_hash = self.get_auction(auction_id)[9]
            sequence = 0
        # se existe bid anterior
        else:
            last_bid = self.get_last_bid(auction_id)
            last_bid_dict = {
                                "PREV_HASH" : last_bid[2],
                                "IDENTITY"   : last_bid[3],
                                "VALUE"      : last_bid[4]
                            }
            prev_hash = SHA256.new(data=json.dumps(last_bid_dict).encode("UTF-8")).hexdigest()
            sequence = last_bid[1] + 1

        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, prev_hash, identity, value) VALUES(?,?,?,?,?)',(auction_id, sequence, prev_hash, identity, value))
        self.db.commit()

        return sequence


    def close(self):
        self.db.commit()
        self.db.close()
