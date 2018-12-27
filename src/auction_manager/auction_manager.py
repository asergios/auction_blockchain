# coding: utf-8

import os
import socket
import json
import logging
import base64
import argparse
from ipaddress import ip_address
from ..common.utils import check_port, load_file_raw, OpenConnections
from ..common.db.manager_db import ADB
from ..common.certmanager import CertManager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)

def main(args):
    pk = load_file_raw('src/auction_manager/keys/private_key.pem')
    pukr = load_file_raw('src/auction_manager/keys/public_key_repository.pem')
    cert = load_file_raw("src/common/certmanager/certs/manager.crt")
    oc = OpenConnections()
    db = ADB()
    
    #switch case para tratar de mensagens
    mActions = {'CREATE':validateAuction,
                'CHALLENGE': challengeResponse,
                'STORE_REPLY': store_reply}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(args.ip_am), args.port_am))

    logger.info('Auction Manager running...')
    while True:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        mActions[j['ACTION']](j, sock, addr, oc, pk, pukr, cert, (str(args.ip_ar), args.port_ar), db)


#responde ao challenge do cliente; retorna um nonce
def challengeResponse(j, sock, addr, oc, pk, pukr, cert, addr_rep, db):
    challenge = base64.urlsafe_b64decode(j['CHALLENGE'])
    certificate = base64.urlsafe_b64decode(j['CERTIFICATE'])

    cm = CertManager(priv_key = pk)
    cr = cm.sign(challenge)
    
    nonce = oc.add(certificate)

    reply = { 'ACTION': 'CHALLENGE_REPLY',
            'CHALLENGE_RESPONSE': base64.urlsafe_b64encode(cr).decode(),
            'CERTIFICATE': base64.urlsafe_b64encode(cert).decode(),
            'NONCE': base64.urlsafe_b64encode(nonce).decode() }
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)


#auction --> client request
def validateAuction(j, sock, addr, oc, pk, pukr, cert, addr_rep, db):
    reply = {'ACTION':'CREATE_REPLY'}

    # Validar assinatura e certificado
    # c = base64.urlsafe_b64decode(j['CERTIFICATE'])
    # @Antonio não precisas de mandar o certificado novamente
    s = base64.urlsafe_b64decode(j['SIGNATURE'])
    message = json.loads(j['MESSAGE'])
    nonce = base64.urlsafe_b64decode(message['NONCE'])
    c = oc.pop(nonce)

    cm = CertManager( cert = c, priv_key = pk )
    if not cm.verify_certificate():
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID CERTIFICATE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return
    
    if not cm.verify_signature(s, j['MESSAGE'].encode('UTF-8')):
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SIGNATURE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    if 'TITLE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TITLE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    if 'DESCRIPTION' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING DESCRIPTION'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    if 'TYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING TYPE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    atype = message['TYPE']
    if atype != 1 and atype != 2:
        logger.debug("type = %d", atype)
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID TYPE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    if 'SUBTYPE' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING SUBTYPE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    subtype = message['SUBTYPE']
    if subtype != 1 and subtype != 2:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'INVALID SUBTYPE'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    
    if 'AUCTION_EXPIRES' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING AUCTION_EXPIRES'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    expires = message['AUCTION_EXPIRES']
    if expires < 0:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'AUCTION_EXPIRES LESS THAN ZERO'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return


    if 'BID_LIMIT' not in message:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'MISSING BID_LIMIT'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    bid_limit = message['BID_LIMIT']
    if bid_limit < 0:
        reply['STATE'] = 'NOT OK'
        reply['ERROR'] = 'BID_LIMIT LESS THAN ZERO'
        logger.error('REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
        return

    nonce = oc.add((cm.get_identity()[1], addr))
    message['ACTION'] = 'STORE'
    message['NONCE'] = base64.urlsafe_b64encode(nonce).decode()
    request = {'ACTION':'STORE', 'DATA': base64.urlsafe_b64encode(cm.encrypt(json.dumps(message).encode('UTF-8'), pukr)).decode()}
    logger.debug("REPOSITORY STORE = %s", request)
    sock.sendto(json.dumps(request).encode('UTF-8'), addr_rep)


def store_reply(j, sock, addr, oc, pk, pukr, cert, addr_rep, db):
    cm = CertManager()
    data = json.loads(cm.decrypt(base64.urlsafe_b64decode(j['DATA']), pk))
    logger.debug('DATA = %s', data)
    nonce = base64.urlsafe_b64decode(data['NONCE'])
    auction_id = data['AUCTION_ID']
    user_cc, user_addr = oc.pop(nonce)
    db.store_user_auction(user_cc, auction_id)
    reply = {'STATE':'OK'}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Auction Manager')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
