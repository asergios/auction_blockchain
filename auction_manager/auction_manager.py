import os
import socket
import json
import logging
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import crypto
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from ..cartaodecidadao import CartaoDeCidadao

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)

UDP_IP = "127.0.0.1"
UDP_PORT = 5001

# classe para gerir as ligações dos multiplos clientes
class OpenConnections:
    def __init__(self):
        self.nonce = 0
        self.openConns = {}
    
    def add(self, certificate):
        self.openConns[self.nonce] = (certificate)
        rv = self.nouce
        self.nonce += 1
        return rv
    
    def get(self, nonce):
        return self.openConns[nonce]


def main():
    backend = default_backend() # VER
    pk = loadPrivateKey("security2018-p1g1/auction_manager/keys/private_key.pem")
    cert = loadCertificate("security2018-p1g1/auction_manager/keys/manager.crt", backend)
    oc = OpenConnections() 
    #switch case para tratar de mensagens
    mActions = {"CREATE":validateAuction,
                "CHALLENGE": challengeResponse}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    logger.info("Auction Manager running...")
    while True:
        data, addr = sock.recvfrom(4096)
        #logger.debug("DATA = %s", data)
        ## FIX ME
        j = json.loads(data)
        j = json.loads(j)
        logger.debug("JSON = %s", j)
        logger.debug("ACTION = %s", j['ACTION'])
        mActions[j["ACTION"]](j, sock, addr, oc, pk, cert)

def loadPrivateKey(path):
    #ftype = crypto.FILETYPE_PEM
    with open(path, 'rb') as f:
        k = RSA.importKey(f.read())
    #k = crypto.load_privatekey(ftype, k)
    return k

def loadCertificate(path, backend):
    with open(path, 'rb') as f: crt_data = f.read()
    cert = x509.load_pem_x509_certificate(crt_data, backend)
    return cert

#responde ao challenge do cliente; retorna um nonce
def challengeResponse(j, sock, addr, oc, pk, cert):
    logger.info("CHALLENGE")
    challenge = base64.urlsafe_b64decode(j["CHALLENGE"])
    certificate = base64.urlsafe_b64decode(j["CERTIFICATE"])

    # cifrar o challenge com a chave privada
    encryptor = PKCS1_OAEP.new(pk)
    cr = encryptor.encrypt(challenge)

    nonce = oc.add(certificate)

    logger.debug("NOUNCE = %d", nonce)
    logger.debug("CHALLENGE RESPONSE = %s", cr)

    reply = { "ACTION": "CHALLENGE_REPLY","CHALLENGE_RESPONSE": base64.urlsafe_b64decode(cr),
              "CERTIFICATE": base64.urlsafe_b64decode(cert),     
              "NONCE": nonce         
            }

    sock.sendto(json.dumps(reply).encode("UTF-8"), addr)


#auction --> client request
def validateAuction(j, sock, addr, oc, pk, cert):
    logger.info("CREATE")
    reply = {"ACTION":"CREATE_REPLY"}
    if "TITLE" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TITLE"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return
    
    if "DESCRIPTION" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING DESCRIPTION"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return
    
    #ver tipos de leiloes
    if "TYPE" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TYPE"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    if "BID_LIMIT" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING BID_LIMIT"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return
    
    #usar o 0 para bid infinita --> não numero limite de bids
    bid_limit = j["BID_LIMIT"]
    if bid_limit < 0:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "BID_LIMIT LESS THAN ZERO"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return

    #verificações extra ?? p.ex ver se o length da lista>0
    if "ALLOWED_BIDDERS" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING ALLOWED_BIDDERS"
        sock.sendto(json.dumps(reply).encode("UTF-8"), addr)
        return
    
    reply["STATE"] = "OK"
    sock.sendto(json.dumps(reply).encode("UTF-8"), addr)

if __name__ == "__main__":
    main()
