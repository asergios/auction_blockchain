# coding: utf-8

import os
import socket
import json
import logging
import base64
import argparse
from ipaddress import ip_address
from ..common.utils import check_port, load_file_raw, OpenConnections
from ..common.certmanager import CertManager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AR')
logger.setLevel(logging.DEBUG)


def main(args):
    pk = load_file_raw("src/auction_repository/keys/private_key.pem")
    pkr = load_file_raw("src/auction_repository/keys/public_key_manager.pem")
    cert = load_file_raw("src/auction_repository/keys/manager.crt")
    oc = OpenConnections()
    
    #switch case para tratar de mensagens
    mActions = {"CREATE":validateAuction,
                "CHALLENGE": challengeResponse}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(args.ip_am), args.port_am))

    logger.info("Auction Manager running...")
    while True:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug("JSON = %s", j)
        logger.debug("ACTION = %s", j['ACTION'])
        mActions[j["ACTION"]](j, sock, addr, oc, pk, cert)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Auction Repository')
    parser.add_argument('--ip_ar', type=ip_address, help='ip address auction repository', default='127.0.0.1')
    parser.add_argument('--port_ar', type=check_port, help='ip port action repository', default=5002)
    parser.add_argument('--ip_am', type=ip_address, help='ip address action manager', default='127.0.0.1')
    parser.add_argument('--port_am', type=check_port, help='ip port action manager', default=5001)
    args = parser.parse_args()
    main(args)
