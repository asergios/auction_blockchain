# coding: utf-8

import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('RDB')
logger.setLevel(logging.DEBUG)

class ADB:
    def __init__(self, path='src/auction_manager/manager.db'):
        self.db = sqlite3.connect(path)

    def store_user_auction(self, user_cc, auction_id):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO users(cc) VALUES (?)', (user_cc,))
        user_id = self.cursor.lastrowid
        cursor.execute('INSERT INTO auctions(user_id, auction_id) VALUES (?,?)', (user_id, auction_id))
        self.db.commit()

    def close(self):
        self.db.commit()
        self.db.close()
