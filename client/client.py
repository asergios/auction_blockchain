import os
import socket
import json
import base64
import sys
from cartaodecidadao import CartaoDeCidadao
sys.path.append("..")	# In order to access modules of previous folder
from common.certmanager import CertManager
from common.logger import initialize_logger
import logging

initialize_logger()

colors = {
		'blue': '\033[94m',
		'pink': '\033[95m',
		'green': '\033[92m',
		'red' : '\033[91m'
		}

UDP_IP = "127.0.0.1"				# Assuming the servers will be local
UDP_PORT_MANAGER = 5001				# Port used for communication with auction manager
UDP_PORT_REPOSITORY = 5002			# Port used for communication with auction repository

# Socket used for communication with manager
sock_manager = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_manager.connect((UDP_IP, UDP_PORT_MANAGER))

# Socket used for communication with repository
sock_repository = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_repository.connect((UDP_IP, UDP_PORT_REPOSITORY))

cc = CartaoDeCidadao()

def clean(clean = False, lines = 2):
	'''
		Cleans previous lines on terminal
	'''
	if clean:
		sys.stdout.write("\033[K")
		return

	sys.stdout.write("\033[" + str(lines) + "F")
	sys.stdout.write("\033[K")

def colorize(string, color):
	'''
		Colorize String For Terminal
	'''
	if not color in colors: return string
	return colors[color] + string + '\033[0m'

def verify_server(certificate, message, signature):
	'''
		Verify Server Certificate and Signature
	'''
	cm = CertManager(cert = certificate)
	return  cm.verify_certificate() and cm.verify_signature( signature , message )

def wait_for_answer(sock):
	'''
		Waits for a response from server
	'''
	while True:
		try:
			data, addr = sock.recvfrom(4096)
			if data:
				return data
		except:
			print( colorize("Unable to connect with server, please try again later.", 'red') )
			input("Press any key to continue...")
			quit()

def create_new_auction(*arg):
	'''
		Creates new auction via auction manager

		JSON sent to Auction Manager Description:

		OUTTER:

		{
			"ACTION" : "CREATE",		# Action we intend auction manager to do, just for easier reading on server-side
			"MESSAGE" : {},				# JSON with all the action description (described bellow)
			"SIGNATURE" : "____",		# Message Signed with CC card
		}

		MESSAGE:

		{
			"ACTION" : "CREATE",		# Action we intend auction manager to do, just for easier reading on server-side
			"TITLE": "_____",			# Title of the auction
			"DESCRIPTION": "_____",		# Description of the auction
			"TYPE": ___,				# Type of the auction 1 being english auction and 2 being blind auction
			"BID_LIMIT": ___,			# Time limit for new bids
		}
	'''
	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Establish connection with server
	print( colorize( "Establishing connection with server, please wait...", 'pink' ) )
	logging.info("Trying to establishing connection with server")

	# Sending challenge to the server
	challenge = os.urandom(64)
	connection = {"ACTION": "CHALLENGE", "CHALLENGE": base64.urlsafe_b64encode( challenge ).decode() ,\
	 			  "CERTIFICATE": base64.urlsafe_b64encode( cc.get_certificate_raw() ).decode() }
	sock_manager.send( json.dumps(connection).encode("UTF-8") )
	logging.info("Sent Challenge To Server: " + json.dumps(connection))

	# Wait for Challenge Response
	server_answer = json.loads( wait_for_answer(sock_manager) )
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	certificate = base64.urlsafe_b64decode( server_answer['CERTIFICATE'].encode() )
	challenge_response = base64.urlsafe_b64decode(server_answer['CHALLENGE_RESPONSE'].encode() )
	logging.info("Verifying certificate and server signature of challenge")

	if not verify_server( certificate, challenge, challenge_response ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")

	new_auction = {}

	clean(lines = 1)

	# Auction Title
	while True:
		new_auction["TITLE"] = input("Title: ")
		if new_auction['TITLE'] != "":
			clean(True)
			break
		else:
			print( colorize('Title can\'t be empty!', 'red') )
			clean()

	# Auction Description
	while True:
		new_auction['DESCRIPTION'] = input("Description: ")
		if new_auction['DESCRIPTION'] != "":
			clean(True)
			break
		else:
			print( colorize('Description can\'t be empty!', 'red') )
			clean()

	# Auction Type
	while True:
		print(colorize('Types available: \n 	1 - English Auction \n 	2 - Blind Auction', 'green'))
		try:
			new_auction['TYPE'] = int(input("Type: "))
		except ValueError:
			print( colorize('Type must be a number!', 'red') )
			clean(lines=5)
			continue
		else:
			if new_auction['TYPE'] == 1 or new_auction['TYPE'] == 2:
				clean(True)
				break
			else:
				print( colorize('Please pick one of the available types.', 'red') )
				clean(lines=5)

	# Auction bids limit per bidder
	while True:
		try:
			new_auction['BID_LIMIT'] = int(input("Limit time for new bids (minutes): "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			clean()
			continue
		else:
			if new_auction['BID_LIMIT'] >= 0:
				clean(True)
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	new_auction["ACTION"] = "CREATE"
	new_auction["NONCE"] = server_answer["NONCE"]
	new_auction = json.dumps(new_auction)

	# Signing and creating outter layer of JSON message
	logging.info("Singning Message To Send Server")
	signed_message = cc.sign( new_auction.encode('UTF-8') )
	outter_message = {"SIGNATURE": base64.urlsafe_b64encode( signed_message ).decode(),
				      "MESSAGE" : new_auction,
					  "ACTION" : "CREATE" }

	# Sending New Auction Request For Auction Manager
	logging.info("Sending Request To Server:" + json.dumps(outter_message))
	sock_manager.send( json.dumps(outter_message).encode("UTF-8") )

	# Wait for Server Response
	logging.info("Waiting for server response")
	print( colorize( "Creating Auction, please wait...", 'pink' ) )
	server_answer = json.loads( wait_for_answer(sock_manager) )
	logging.info("Received Server Response: " + json.dumps(server_answer))

	if (server_answer["STATE"] == "OK"):
		clean(lines=1)
		print( colorize("Auction succesfully created!", 'pink') )
		input("Press any key to continue...")
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		print( colorize("Something really weird happen, please fill a bug report.", 'red') )
		input("Press any key to continue...")


def list_auction(auction_type, auction_id = None):
	'''
		Requests english auctions to auction repository

		JSON sent to Auction Repository Description:

		{
			"ACTION" : "ENGLISH/BLIND",
			(Optional) "AUCTION_ID" : XX
		}
	'''

	request = {"ACTION" : auction_type}

	if auction_id:
		request["AUCTION_ID"] = auction_id

	# Covert to JSON string
	request = json.dumps(request)
	# Send request to repository
	sock_repository.send(request.encode("UTF-8"))
	# Waiting for server response
	server_answer = json.loads( wait_for_answer(sock_repository) )

	'''
		I will be expecting an answer in this format:
		{
			"SIGNED_LIST": 		// Signed list of english auctions
			"CERTIFICATE":		// Certificate of public key of the server
			"LIST":				// Raw List of Auctions
		}
	'''

	# Verify server certificate and verify signature of auction list
	certificate = base64.urlsafe_b64decode( server_answer['CERTIFICATE'].encode() )
	signature = base64.urlsafe_b64decode(server_answer['SIGNED_LIST'].encode() )
	plain = base64.urlsafe_b64decode(server_answer['LIST'].encode() )
	if not verify_server( certificate, plain, signature ):
		print( colorize('Server Validation Failed!', 'red') )
		quit()

	# TODO: rest of this
	pass


# Menu to be printed to the user
menu = [
    { "Create new auction": (create_new_auction, None) },
    { "List open auctions [English Auction]": (list_auction, "ENGLISH") },
    { "List open auctions [Blind Auction]": (list_auction, "BLIND") },
	{ "Exit" : None }
]

def main():
	while True:
		os.system('clear')													# Clear the terminal
		ascii = open('../common/ascii', 'r')								# Reading the sick ascii art
		print( colorize(ascii.read(), 'pink') )								# Printing the ascii art as pink
		ascii.close()
		print('\n')
		for item in menu:													# Printing the menu together with the index
			print( str(menu.index(item) + 1) + " - " + list(item.keys())[0] )

		choice = input(">> ")

		try:																# Reading the choice
			if int(choice) <= 0 : raise ValueError
			if int(choice) == 4 : quit()
			list(menu[int(choice) - 1].values())[0][0](list(menu[int(choice) - 1].values())[0][1])
		except (ValueError, IndexError):
			pass

if __name__ == "__main__":
    main()
