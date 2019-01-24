# coding: utf-8

import sqlite3
import logging
from datetime import datetime, timedelta
from ..certmanager import CertManager


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ADB')
logger.setLevel(logging.DEBUG)


class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path)

    def store_auction(self, title, desc, atype, subtype, duration):
        start = datetime.now()
        stop = (start + timedelta(hours=duration)).timestamp() if duration > 0 else 0
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, duration, start, stop) VALUES(?,?,?,?,?,?,?)',
                (title, desc, atype, subtype, duration, start, stop))
        rv = cursor.lastrowid
        self.db.commit()
        return rv

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

    def last_sequence(self, auction_id):
        ls = -1

        cursor = self.db.cursor()
        cursor.execute('SELECT sequence FROM bids WHERE auction_id=? ORDER BY sequence DESC', (auction_id,))
        rows = cursor.fetchall()

        if len(rows) > 0:
            ls = rows[0][0]

        return ls

    def store_bid(self, auction_id, certificate, value):
        sequence = self.last_sequence(auction_id) + 1

        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, certificate, value) VALUES(?,?,?,?)',(auction_id, sequence, certificate, value))
        self.db.commit()

        return sequence


    def close(self):
        self.db.commit()
        self.db.close()
