# coding: utf-8

import os
import socket
import json
import logging
import base64
import argparse
from ipaddress import ip_address
from ..common.utils import check_port, load_file_raw, OpenConnections
from ..common.db.repository_db import RDB
from ..common.certmanager import CertManager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AR')
logger.setLevel(logging.DEBUG)


def main(args):
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    pukm = load_file_raw('src/auction_repository/keys/public_key_manager.pem')
    db = RDB()
    #oc = OpenConnections()
    
    #switch case para tratar de mensagens
    mActions = {'STORE':storageAuction}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(args.ip_ar), args.port_ar))

    logger.info('Auction Repository running...')
    while True:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        mActions[j['ACTION']](j, sock, addr, pk, pukm, db)


def storageAuction(j, sock, addr, pk, pukm, db):
    cm = CertManager()
    data = json.loads(cm.decrypt(base64.urlsafe_b64decode(j['DATA']), pk))
    logger.debug('DATA = %s', data)
    auction_id = db.store_auction(data['TITLE'], data['DESCRIPTION'], data['TYPE'], data['SUBTYPE'], data['AUCTION_EXPIRES'], data['BID_LIMIT'])
    nonce = data['NONCE']
    data = {'NONCE':nonce, 'AUCTION_ID':auction_id}
    reply = {'ACTION':'STORE_REPLY', 'DATA': base64.urlsafe_b64encode(cm.encrypt(json.dumps(data).encode('UTF-8'), pukm)).decode()}
    logger.debug('MANAGER REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Repository')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
