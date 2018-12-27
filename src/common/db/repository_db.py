# coding: utf-8

import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ADB')
logger.setLevel(logging.DEBUG)

class RDB:
    def __init__(self, path='src/auction_repository/repository.db'):
        self.db = sqlite3.connect(path)
        self.cursor = self.db.cursor()

    def store_auction(self, title, desc, atype, subtype, expires, limit):
        self.cursor.execute('INSERT INTO auctions(title, desc, type, subtype, blimit, expires) VALUES(?,?,?,?,?,?)',
                (title, desc, atype, subtype, expires, limit))
        return self.cursor.lastrowid

    def close(self):
        self.cursor.close()
        self.db.close()
