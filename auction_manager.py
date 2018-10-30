import os
import socket
import json

UDP_IP = "127.0.0.1"
UDP_PORT = 5001

#switch case para tratar de mensagens
mActions = {"CREATE":validateAuction}

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

while True:
	 data, addr = sock.recvfrom(1024)
	 j = json.loads(data)
	 mActions[j["ACTION"]](j, addr)

#auction --> client request
def validateAuction(j, addr):
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
	if bid_limit > 0:
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




