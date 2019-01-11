# coding: utf-8

import os
import socket
import json
import logging
import base64
import argparse
import signal
from functools import partial
from ipaddress import ip_address
from ..common.utils import check_port, load_file_raw, OpenConnections
from ..common.db.repository_db import RDB
from ..common.certmanager import CertManager


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AR')
logger.setLevel(logging.DEBUG)


def signal_handler(addr, signal, frame):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'EXIT'}).encode('UTF-8'), addr)


def main(args):
    addr = (str(args.ip_ar), args.port_ar)
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    pukm = load_file_raw('src/auction_repository/keys/public_key_manager.pem')
    cert = load_file_raw("src/common/certmanager/certs/repository.crt")
    db = RDB()
    #oc = OpenConnections()

    signal.signal(signal.SIGINT, partial(signal_handler, addr))

    #switch case para tratar de mensagens
    mActions = {'STORE':storage_auction,
            'ENGLISH':list_english,
            'BLIND':list_blind,
            'BID_INIT':bid_init
            'EXIT':exit}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(addr)

    logger.info('Auction Repository running...')
    done = False
    while not done:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        done = mActions[j['ACTION']](j, sock, addr, pk, pukm, cert, db)


def storage_auction(j, sock, addr, pk, pukm, cert, db):
    cm = CertManager()
    data = json.loads(cm.decrypt(base64.urlsafe_b64decode(j['DATA']), pk))
    logger.debug('DATA = %s', data)
    auction_id = db.store_auction(data['TITLE'], data['DESCRIPTION'], data['TYPE'], data['SUBTYPE'], data['AUCTION_EXPIRES'], data['BID_LIMIT'])
    nonce = data['NONCE']
    data = {'NONCE':nonce, 'AUCTION_ID':auction_id}
    reply = {'ACTION':'STORE_REPLY', 'DATA': base64.urlsafe_b64encode(cm.encrypt(json.dumps(data).encode('UTF-8'), pukm)).decode()}
    logger.debug('MANAGER REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def list_english(j, sock, addr, pk, pukm, cert, db):
    nonce = base64.urlsafe_b64decode(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']
    rows = db.list_english(auction_id)

    if auction_id is None:
        l = []
        for row in rows:
            d = {'AUCTION_ID':row[0], 'TITLE':row[1]}
            l.append(d)
        message = {'NONCE':base64.urlsafe_b64encode(nonce).decode(), 'LIST':l}
    else:
        auction = {}
        if len(rows) == 1:
            row = rows[0]
            auction['AUCTION_ID'] = row[0]
            auction['TITLE'] = row[1]
            auction['DESCRIPTION'] = row[2]
            auction['TYPE'] = row[3]
            auction['SUBTYPE'] = row[4]
            auction['ENDING_TIMESTAMP'] = row[5]
            auction['WHO_HIDES'] = None
            auction['BIDS'] = []
        message = {'NONCE':base64.urlsafe_b64encode(nonce).decode(), 'AUCTION':auction}
    cm = CertManager(priv_key = pk)
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = { 'ACTION': 'ENGLISH_REPLY',
            'SIGNATURE': base64.urlsafe_b64encode(sl).decode(),
            'CERTIFICATE': base64.urlsafe_b64encode(cert).decode(),
            'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    return False


def list_blind(j, sock, addr, pk, pukm, cert, db):
    nonce = base64.urlsafe_b64decode(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']
    rows = db.list_blind(auction_id)

    if auction_id is None:
        l = []
        for row in rows:
            d = {'AUCTION_ID':row[0], 'TITLE':row[1]}
            l.append(d)
        message = {'NONCE':base64.urlsafe_b64encode(nonce).decode(), 'LIST':l}
    else:
        auction = {}
        if len(rows) == 1:
            row = rows[0]
            auction['AUCTION_ID'] = row[0]
            auction['TITLE'] = row[1]
            auction['DESCRIPTION'] = row[2]
            auction['TYPE'] = row[3]
            auction['SUBTYPE'] = row[4]
            auction['ENDING_TIMESTAMP'] = row[7]
            auction['WHO_HIDES'] = None
            auction['BIDS'] = []
        message = {'NONCE':base64.urlsafe_b64encode(nonce).decode(), 'AUCTION':auction}
    cm = CertManager(priv_key = pk)
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = { 'ACTION': 'BLIND_REPLY',
            'SIGNATURE': base64.urlsafe_b64encode(sl).decode(),
            'CERTIFICATE': base64.urlsafe_b64encode(cert).decode(),
            'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    return False


def bid_init(j, sock, addr, pk, pukm, cert, db):
    certificate = base64.urlsafe_b64decode(j['CERTIFICATE'])
    auction_id = j['AUCTION_ID']

    

    return False


def exit(j, sock, addr, pk, pukm, cert, db):
    logger.debug("EXIT")
    db.close()
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Repository')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
