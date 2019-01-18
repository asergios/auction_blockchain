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
from ..common.utils import check_port, load_file_raw, OpenConnections, toBase64, fromBase64
from ..common.db.manager_db import ADB
from ..common.certmanager import CertManager
from ..common.cryptmanager import decrypt


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)


def signal_handler(addr, signal, frame):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'EXIT'}).encode('UTF-8'), addr)


def main(args):
    addr = (str(args.ip_am), args.port_am)
    addr_rep = (str(args.ip_ar), args.port_ar)
    oc = OpenConnections()
    db = ADB()

    signal.signal(signal.SIGINT, partial(signal_handler, addr))

    mActions = {'CREATE':validate_auction,
                'CHALLENGE': challenge,
                'STORE_REPLY': store,
                'VALIDATE_BID': validate_bid,
                'EXIT': exit}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(addr)

    logger.info('Auction Manager running...')
    done = False
    while not done:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        done = mActions[j['ACTION']](j, sock, addr, oc, addr_rep, db)


def challenge(j, sock, addr, oc, addr_rep, db):
    challenge = fromBase64(j['CHALLENGE'])
    certificate = fromBase64(j['CERTIFICATE'])

    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    cr = cm.sign(challenge)

    nonce = oc.add(certificate)

    reply = {'ACTION': 'CHALLENGE_REPLY',
            'CHALLENGE_RESPONSE': toBase64(cr),
            'CERTIFICATE': toBase64(cert),
            'NONCE': toBase64(nonce)}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def validate_auction(j, sock, addr, oc, addr_rep, db):
    reply = {'ACTION':'CREATE_REPLY'}

    s = fromBase64(j['SIGNATURE'])
    message = json.loads(j['MESSAGE'])
    nonce = fromBase64(message['NONCE'])
    cm = CertManager(cert = oc.pop(nonce))

    if not cm.verify_certificate():
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID CERTIFICATE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if not cm.verify_signature(s, j['MESSAGE'].encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'TITLE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TITLE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'DESCRIPTION' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING DESCRIPTION'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'TYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    atype = message['TYPE']
    if atype != 1 and atype != 2:
        logger.debug("type = %d", atype)
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID TYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'SUBTYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING SUBTYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    subtype = message['SUBTYPE']
    if subtype != 1 and subtype != 2:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SUBTYPE'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'AUCTION_EXPIRES' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING AUCTION_EXPIRES'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    expires = message['AUCTION_EXPIRES']
    if expires < 0:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'AUCTION_EXPIRES LESS THAN ZERO'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    if 'BID_LIMIT' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING BID_LIMIT'
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    bid_limit = message['BID_LIMIT']
    if bid_limit < 0:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'BID_LIMIT LESS THAN ZERO'
        logger.error('REPLY CLIENT = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    nonce = oc.add((cm.get_identity()[1], addr))
    message['ACTION'] = 'STORE'
    message['NONCE'] = toBase64(nonce)
    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
    request = {'ACTION':'STORE', 'DATA': toBase64(cm.encrypt(json.dumps(message).encode('UTF-8')))}
    logger.debug("REPOSITORY STORE = %s", request)
    sock.sendto(json.dumps(request).encode('UTF-8'), addr_rep)
    return False


def store(j, sock, addr, oc, addr_rep, db):
    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    data = json.loads(cm.decrypt(fromBase64(j['DATA'])))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    auction_id = data['AUCTION_ID']
    user_cc, user_addr = oc.pop(nonce)
    db.store_user_auction(user_cc, auction_id)
    reply = {'ACTION': 'CREATE_REPLY', 'STATE':'OK'}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), user_addr)
    return False


def validate_bid(j, sock, addr, oc, addr_rep, db):
    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    data = json.loads(cm.decrypt(fromBase64(j['DATA'])))
    logger.debug('DATA = %s', data)
    nonce = data['NONCE']
    message = data['MESSAGE']
    signature = data['SIGNATURE']
    message = data['MESSAGE']
    certificate = fromBase64(message['CERTIFICATE'])
    value = fromBase64(message['VALUE'])

    if 'MANAGER_SECRET' in data:
        secret = data['MANAGER_SECRET']
        certificate = decrypt(certificate)
        value = decrypt(value)
    
    cm = CertManager(cert = certificate)

    if not cm.verify_certificate():
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID SIGNATURE', 'NONCE': nonce}
        cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
        reply = {'ACTION': 'VALIDATE_BID_REPLY',
                'DATA': toBase64(cm.encrypt(json.dumps(message).encode('UTF-8')))}
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False


    if not cm.verify_signature(signature, message.encode('UTF-8')):
        data = {'STATE': 'NOT OK', 'ERROR': 'INVALID SIGNATURE', 'NONCE': nonce}
        cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
        reply = {'ACTION': 'VALIDATE_BID_REPLY',
                'DATA': toBase64(cm.encrypt(json.dumps(message).encode('UTF-8')))}
        logger.debug('REPOSITORY REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return False

    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    if 'MANAGER_SECRET' in data:
        message['CERTIFICATE'] = toBase64(cm.encrypt(certificate))
        message['VALUE'] = toBase64(cm.encrypt(value))
    onion = {'ONION_0': message, 'SIGNATURE': signature}
    data = {'ONION_1': onion, 'SIGNATURE': toBase64(cm.sign(onion.encode('UTF-8'))),'NONCE': nonce, 'STATE': 'OK'}
    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
    reply = {'ACTION': 'VALIDATE_BID_REPLY', 'DATA': toBase64(cm.encrypt(json.dumps(data).encode('UTF-8')))}
    logger.debug('REPOSITORY REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def exit(j, sock, addr, oc, addr_rep, db):
    logger.debug("EXIT")
    db.close()
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Manager')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
