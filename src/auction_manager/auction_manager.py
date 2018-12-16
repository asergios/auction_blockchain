import os
import socket
import json
import logging
import base64
from ..common.certmanager import CertManager

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)

UDP_IP = "127.0.0.1"
UDP_PORT = 5001

# classe para gerir as ligações dos multiplos clientes
class OpenConnections:
    def __init__(self):
        self.nonce = os.urandom(16)
        self.openConns = {}

    def add(self, certificate):
        self.openConns[self.nonce] = (certificate)
        rv = self.nonce
        self.nonce = os.urandom(16)
        return rv

    def get(self, nonce):
        return self.openConns[nonce]


def main():
    pk = loadPrivateKey("src/auction_manager/keys/private_key.pem")
    cert = loadCertificateRaw("src/auction_manager/keys/manager.crt")
    oc = OpenConnections()
    
    #switch case para tratar de mensagens
    mActions = {"CREATE":validateAuction,
                "CHALLENGE": challengeResponse}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    logger.info("Auction Manager running...")
    while True:
        data, addr = sock.recvfrom(4096)
        j = json.loads(data)
        logger.debug("JSON = %s", j)
        logger.debug("ACTION = %s", j['ACTION'])
        mActions[j["ACTION"]](j, sock, addr, oc, pk, cert)

def loadPrivateKey(path):
    with open(path, 'rb') as f:
        k = f.read()
    return k

def loadCertificateRaw(path):
    with open(path, 'rb') as f: crt_data = f.read()
    return crt_data

#responde ao challenge do cliente; retorna um nonce
def challengeResponse(j, sock, addr, oc, pk, cert):
    challenge = base64.urlsafe_b64decode(j["CHALLENGE"])
    certificate = base64.urlsafe_b64decode(j["CERTIFICATE"])

    # Assinar Challenge
    # Ver este ponto da comunicação...
    cm = CertManager( priv_key = pk )
    cr = cm.sign(challenge)
    
    nonce = oc.add(certificate)

    reply = { "ACTION": "CHALLENGE_REPLY","CHALLENGE_RESPONSE": base64.urlsafe_b64encode(cr).decode(),
              "CERTIFICATE": base64.urlsafe_b64encode(cert).decode(),
              "NONCE": base64.urlsafe_b64encode(nonce).decode() }
    logger.debug("Reply = %s", reply)

    sock.sendto(json.dumps(reply).encode("UTF-8"), addr)


#auction --> client request
def validateAuction(j, sock, addr, oc, pk, cert):
    reply = {"ACTION":"CREATE_REPLY"}

    # Validar assinatura e certificado
    c = base64.urlsafe_b64decode(j['CERTIFICATE'])
    s = base64.urlsafe_b64decode(j['SIGNATURE'])
    message = json.loads(j["MESSAGE"])
    nonce = base64.urlsafe_b64decode(message['NONCE'])

    cm = CertManager( cert = c, priv_key = pk )
    if not cm.verify_certificate():
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "INVALID CERTIFICATE"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return
    
    if not cm.verify_signature(s, j["MESSAGE"].encode("UTF-8")):
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "INVALID SIGNATURE"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    if "TITLE" not in message:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TITLE"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    if "DESCRIPTION" not in message:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING DESCRIPTION"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    #ver tipos de leiloes
    if "TYPE" not in message:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TYPE"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    if "BID_LIMIT" not in message:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING BID_LIMIT"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    #usar o 0 para bid infinita --> não numero limite de bids
    bid_limit = message["BID_LIMIT"]
    if bid_limit < 0:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "BID_LIMIT LESS THAN ZERO"
        logger.error("REPLY = %s", reply)
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    reply["STATE"] = "OK"
    logger.error("REPLY = %s", reply)
    sock.sendto(json.dumps(reply).encode("UTF-8"), addr)

if __name__ == "__main__":
    main()
