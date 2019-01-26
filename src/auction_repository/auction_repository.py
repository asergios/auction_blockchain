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
from ..common.db.repository_db import RDB
from ..common.certmanager import CertManager
from ..common.cryptopuzzle import CryptoPuzzle


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AR')
logger.setLevel(logging.DEBUG)

# Needs to be global so it can store the puzzles sent
cp =  CryptoPuzzle()


def signal_handler(addr, signal, frame):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('',0))
    sock.sendto(json.dumps({'ACTION':'EXIT'}).encode('UTF-8'), addr)


def main(args):
    addr = (str(args.ip_ar), args.port_ar)
    addr_man = (str(args.ip_am), args.port_am)
    #pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    #pukm = load_file_raw('src/auction_repository/keys/public_key_manager.pem')
    #cert = load_file_raw("src/common/certmanager/certs/repository.crt")
    db = RDB()
    oc = OpenConnections()

    signal.signal(signal.SIGINT, partial(signal_handler, addr))

    #switch case para tratar de mensagens
    mActions = {'STORE': store,
            'LIST' : list_auctions,
            'CRYPTOPUZZLE': cryptopuzzle,
            'OFFER': offer,
            'VALIDATE_BID_REPLY':validate_bid,
            'EXIT': exit}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(addr)

    logger.info('Auction Repository running...')
    done = False
    while not done:
        data, addr = sock.recvfrom(8192)
        print(data)
        j = json.loads(data)
        logger.debug('JSON = %s', j)
        done = mActions[j['ACTION']](j, sock, addr, oc, cryptopuzzle, addr_man, db)


def store(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
    #data = json.loads(cm.decrypt(fromBase64(j['DATA'])))
    ## TEMPORARY FIX
    data = json.loads(fromBase64(j['DATA']))
    logger.debug('DATA = %s', data)
    auction_id = db.store_auction(data['TITLE'], data['DESCRIPTION'], data['TYPE'], data['SUBTYPE'], data['WHO_HIDES'],data['AUCTION_EXPIRES'])
    nonce = data['NONCE']
    data = {'NONCE':nonce, 'AUCTION_ID':auction_id}

    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    #reply = {'ACTION':'STORE_REPLY', 'DATA': toBase64(cm.encrypt(json.dumps(data).encode('UTF-8')))}
    # TEMPORARY FIX
    reply = {'ACTION':'STORE_REPLY', 'DATA': toBase64(json.dumps(data).encode('UTF-8'))}
    logger.debug('MANAGER REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def list_auctions(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    nonce = fromBase64(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']

    if isinstance(auction_id, list) or auction_id is None:
        auctions = db.list_global(auction_id)

        for_client = []
        for auction in auctions:
            l = {
                    "AUCTION_ID" : auction[0],
                    "TITLE" : auction[1],
                    "TYPE"  : auction[3]
                }
            for_client.append(l)
        message = {'NONCE':toBase64(nonce), 'LIST':for_client}

    else:
        row = db.list_global([auction_id])[0]

        auction = {}
        bids_db = db.get_bids(auction_id)
        bids = []
        for bid in bids_db:
            bids.append({
                             "PREV_HASH" : bid[2],
                             "IDENTITY"   : bid[3],
                             "VALUE"      : bid[4]
                        })

        auction['AUCTION_ID'] = row[0]
        auction['TITLE'] = row[1]
        auction['DESCRIPTION'] = row[2]
        auction['TYPE'] = row[3]
        auction['SUBTYPE'] = row[4]
        auction['ENDING_TIMESTAMP'] = row[8]
        auction['SEED'] = row[9]
        auction['WHO_HIDES'] = row[5]
        auction['BIDS'] = bids
        message = {'NONCE':toBase64(nonce), 'AUCTION':auction}

    # TODO: You need the private key for signing
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    cert = CertManager.get_cert_by_name('repository.crt')

    cm = CertManager(cert = cert, priv_key = pk)
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = { 'ACTION': 'LIST_REPLY',
            'SIGNATURE': toBase64(sl),
            'CERTIFICATE': toBase64(cert),
            'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    return False


# Not being used, just here as backup
'''
def list_english(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    nonce = fromBase64(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']
    rows = db.list_english(auction_id)

    if auction_id is None:
        l = []
        for row in rows:
            d = {'AUCTION_ID':row[0], 'TITLE':row[1]}
            l.append(d)
        message = {'NONCE':toBase64(nonce), 'LIST':l}
    else:
        auction = {}
        bids_db = db.get_bids(auction_id)
        bids = []
        for bid in bids_db:
            bids.append({
                             "PREV_HASH" : bid[2],
                             "IDENTITY"   : bid[3],
                             "VALUE"      : bid[4]
                        })

        if len(rows) == 1:
            row = rows[0]
            auction['AUCTION_ID'] = row[0]
            auction['TITLE'] = row[1]
            auction['DESCRIPTION'] = row[2]
            auction['TYPE'] = row[3]
            auction['SUBTYPE'] = row[4]
            auction['ENDING_TIMESTAMP'] = row[7]
            auction['SEED'] = row[8]
            auction['WHO_HIDES'] = None
            auction['BIDS'] = bids
        message = {'NONCE':toBase64(nonce), 'AUCTION':auction}

    # TODO: You need the private key for signing
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    cert = CertManager.get_cert_by_name('repository.crt')

    cm = CertManager(cert = cert, priv_key = pk)
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = { 'ACTION': 'ENGLISH_REPLY',
            'SIGNATURE': toBase64(sl),
            'CERTIFICATE': toBase64(cert),
            'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    return False


def list_blind(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    nonce = fromBase64(j['NONCE'])
    auction_id = None
    if 'AUCTION_ID' in j:
        auction_id = j['AUCTION_ID']
    rows = db.list_blind(auction_id)

    if auction_id is None:
        l = []
        for row in rows:
            d = {'AUCTION_ID':row[0], 'TITLE':row[1]}
            l.append(d)
        message = {'NONCE':toBase64(nonce), 'LIST':l}
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
        message = {'NONCE':toBase64(nonce), 'AUCTION':auction}

    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'))
    sl = cm.sign(json.dumps(message).encode('UTF-8'))

    reply = { 'ACTION': 'BLIND_REPLY',
            'SIGNATURE': toBase64(sl),
            'CERTIFICATE': toBase64(cert),
            'MESSAGE': message}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)

    return False
'''

def cryptopuzzle(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    auction_id = j['AUCTION_ID']
    certificate = fromBase64(j['IDENTITY'])
    (puzzle, starts, ends) = cp.create_puzzle(certificate)
    nonce = j['NONCE']
    message = { 'PUZZLE':puzzle,
                'STARTS_WITH': toBase64(starts),
                'ENDS_WITH':toBase64(ends),
                'NONCE': nonce}

    # TODO: You need the private key for signing
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    cert = CertManager.get_cert_by_name('repository.crt')

    cm = CertManager(cert = cert, priv_key = pk)

    signature = cm.sign(json.dumps(message).encode('UTF-8'))
    reply = { 'ACTION': 'CRYPTOPUZZLE_REPLY',
            'MESSAGE': message,
            'SIGNATURE': toBase64(signature),
            'CERTIFICATE': toBase64(cert)}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def offer(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    message = j['MESSAGE']
    solution = fromBase64(message['SOLUTION'])
    # Verificar CryptoPuzzle
    if cp.validate_solution(fromBase64(message['IDENTITY']), solution):
        auction = db.get_auction(int(message["AUCTION"]))

        hidden_value = (auction[3] == 2)
        hidden_identity = (auction[4] == 2)
        manager_hides = (auction[5] == 2)

        # Se for o manager a esconder ele ja tem de tratar da validacao da bid
        if manager_hides:
            # Se isto acontecer o client nao compriu a norma... error
            if not 'MANAGER_SECRET' in j:
                reply={'ACTION':'RECEIPT', 'STATE': 'NOT OK', 'ERROR':'AUCTION REQUIREMENTS NOT MET'}
                logger.debug('CLIENT REPLY = %s', reply)
                sock.sendto(json.dumps(reply).encode('UTF-8'), addr)


            # TODO: Faltam coisas para o manager validar a bid (argumentos para o codigo dinamico, valor da ultima oferta etc)
            nonce = toBase64(oc.add(addr))
            data = {    'MESSAGE':message,
                        'SIGNATURE': j['SIGNATURE'],
                        'NONCE':nonce,
                        'HIDDEN_VALUE': hidden_value,
                        'HIDDEN_IDENTITY' : hidden_identity,
                        'MANAGER_SECRET' : j['MANAGER_SECRET'],
                        'CERTIFICATE' : j['CERTIFICATE']}

            # TODO: a message é demasiado longa para ser cifrada com uma chave assimetrica / da erro
            #request = {'ACTION':'VALIDATE_BID', 'DATA':toBase64(cm.encrypt(json.dumps(message).encode('UTF-8')))}
            #### TEMPORARY FIX
            # Na minha opiniao, devias simplesmente assinar a mensagem mas ve como queres
            request = {'ACTION':'VALIDATE_BID', 'DATA': data }
            logger.debug('MANAGER REQUEST = %s', request)
            sock.sendto(json.dumps(request).encode('UTF-8'), addr_man)

        # TODO: Armazenar caso seja CLIENT HIDES
        # Senao, o repositorio ja pode armazenar, a validacao é feita ao fim
        else:
            pass
    else:
        reply={'ACTION':'RECEIPT', 'STATE': 'NOT OK', 'ERROR':'INVALID OR LATE CRYPTOPUZZLE'}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr)
    return False


def validate_bid(j, sock, addr, oc, cryptopuzzle, addr_man, db):
    cm = CertManager(cert = CertManager.get_cert_by_name('manager.crt'))
    #data = json.loads(cm.decrypt(fromBase64(j['DATA'])))
    #### TEMPORARY FIX
    data = json.loads(fromBase64(j['DATA']))
    logger.debug('DATA = %s', data)
    nonce = fromBase64(data['NONCE'])
    addr_client = oc.pop(nonce)

    state = data['STATE']

    if state == "NOT OK":
        reply = {'ACTION': 'RECEIPT', 'STATE': state, 'ERROR': data['ERROR']}
        logger.debug('CLIENT REPLY = %s', reply)
        sock.sendto(json.dumps(reply).encode('UTF-8'), addr_client)
        return False
    onion1 = data['ONION_1']
    onion0 = onion1['ONION_0']
    identity = onion0['IDENTITY']
    value = onion0['VALUE']
    auction_id = onion0['AUCTION']

    prev_hash = db.store_bid(auction_id, identity, value)

    # TODO: You need the private key for signing
    pk = load_file_raw('src/auction_repository/keys/private_key.pem')
    cm = CertManager(cert = CertManager.get_cert_by_name('repository.crt'), priv_key = pk)

    onion2 = {'ONION_1': onion1, 'SIGNATURE': data['SIGNATURE'], 'PREV_HASH': prev_hash}
    signature_repository = cm.sign(json.dumps(onion2).encode('UTF-8'))
    reply = {'ACTION': 'RECEIPT', 'RECEIPT': {"ONION_2" : onion2, 'SIGNATURE': toBase64(signature_repository)}}
    logger.debug('CLIENT REPLY = %s', reply)
    sock.sendto(json.dumps(reply).encode('UTF-8'), addr_client)

    return False


def exit(j, sock, addr, oc, cryptopuzzle, addr_man, db):
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
