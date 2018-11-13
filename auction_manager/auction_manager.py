import os
import socket
import json
import logging
from ..cartaodecidadao import CartaoDeCidadao

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('AM')
logger.setLevel(logging.DEBUG)

UDP_IP = "127.0.0.1"
UDP_PORT = 5001

def main():
    #switch case para tratar de mensagens
    mActions = {"CREATE":validateAuction}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    logger.info("Auction Manager running...")
    while True:
        data, addr = sock.recvfrom(1024)
        j = json.loads(data)
        logger.debug(j)
        mActions[j["ACTION"]](j, sock, addr)

#auction --> client request
def validateAuction(j, sock, addr):
    reply = {"ACTION":"REPLY"}
    if "TITLE" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TITLE"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return
    
    if "DESCRIPTION" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING DESCRIPTION"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return
    
    #ver tipos de leiloes
    if "TYPE" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING TYPE"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return

    if "BID_LIMIT" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING BID_LIMIT"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return
    
    #usar o 0 para bid infinita --> não numero limite de bids
    bid_limit = j["BID_LIMIT"]
    if bid_limit < 0:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "BID_LIMIT LESS THAN ZERO"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return

    #verificações extra ?? p.ex ver se o length da lista>0
    if "ALLOWED_BIDDERS" not in j:
        reply["STATE"] = "NOT OK"
        reply["ERROR"] = "MISSING ALLOWED_BIDDERS"
        sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)
        return
    
    reply["STATE"] = "OK"
    sock.sendto(str(json.dumps(reply)).encode("UTF-8"), addr)

if __name__ == "__main__":
    main()
