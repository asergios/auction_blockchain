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

    def store_auction(self, title, desc, atype, subtype, duration, limit):
        start = datetime.now()
        stop = start + timedelta(hours=duration) if duration > 0 else 0
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO auctions(title, desc, type, subtype, duration, start, stop, blimit) VALUES(?,?,?,?,?,?,?,?)',
                (title, desc, atype, subtype, duration, start, stop, limit))
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

    def get_hash(self, auction_id, sequence):
        h = None

        cursor = self.db.cursor()
        cursor.execute('SELECT hash FROM bids WHERE auction_id=? AND sequence=?', (auction_id, sequence))
        rows = cursor.fetchall()

        if len(rows) > 0:
            h = rows[0][0]

        return h
    
    def store_bid(self, pkey, auction_id, value, certificate, puzzle, solution):
        ls = last_sequence(auction_id)
        lh = None

        if ls >= 0:
            lh = get_hash(auction_id, ls)
        
        data = {'AUCTION_ID':auction_id, 'VALUE':value, 'CERTIFICATE':certificate,
                'PUZZLE':puzzle, 'SOLUTION':solution, 'SEQUENCE':(ls+1), 'PREVIOUS_HASH':lh}

        cm = CertManager()
        h='DUMMY'
        #h = base64.urlsafe_b64encode(cm.encrypt(json.dumps(message).encode('UTF-8'), pkey)).decode()
        
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO bids(auction_id, sequence, hash) VALUES(?,?,?)',(auction_id, (ls+1), h))
        self.db.commit()

        return (ls+1)


    def close(self):
        self.db.commit()
        self.db.close()
