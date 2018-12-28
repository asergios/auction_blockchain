# coding: utf-8

import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ADB')
logger.setLevel(logging.DEBUG)

class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path)

    def store_auction(self, title, desc, atype, subtype, expires, limit):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, blimit, expires) VALUES(?,?,?,?,?,?)',
                (title, desc, atype, subtype, expires, limit))
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

    def close(self):
        self.db.commit()
        self.db.close()
