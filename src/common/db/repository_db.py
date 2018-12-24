# coding: utf-8

import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RDB')
logger.setLevel(logging.DEBUG)

class RDB:
    def __init__(self, path='repository.db'):
        self.db = sqlite3.connect(path)
        self.cursor = self.db.cursor()

    def store_auction(self, title, desc, atype, subtype, expires, limit):
        cursor.execute('INSERT INTO auctions (title,desc,type,subtype,expires,limit) VALUES (?,?,?,?,?,?)',
                (title, desc, atype, subtype, expires, limit))
        return cursor.lastrowid

    def close(self):
        self.cursor.close()
        self.db.close()
