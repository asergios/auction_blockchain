import os
import socket
import json
import base64
import sys
import platform
import subprocess
from .cartaodecidadao import CartaoDeCidadao
from ..common.certmanager import CertManager
from ..common.cryptopuzzle import CryptoPuzzle
from ..common.cryptmanager import *
from ..common.logger import initialize_logger
import logging


initialize_logger("security2018-p1g1/client")

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

def toBase64(content):
	return base64.urlsafe_b64encode(content).decode()

def fromBase64(base64string):
	return base64.urlsafe_b64decode(base64string.encode("UTF-8"))

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
			logging.error("Failed to connect to server!")
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
			"CERTIFICATE" : "____"		# CC certificate
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
	connection = {"ACTION": "CHALLENGE", "CHALLENGE":  toBase64(challenge)  ,\
	 			  "CERTIFICATE": toBase64(cc.get_certificate_raw()) }
	sock_manager.send( json.dumps(connection).encode("UTF-8") )
	logging.info("Sent Challenge To Server: " + json.dumps(connection))

	# Wait for Challenge Response
	server_answer = json.loads( wait_for_answer(sock_manager) )
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	certificate = fromBase64( server_answer['CERTIFICATE'] )
	challenge_response = fromBase64( server_answer['CHALLENGE_RESPONSE'] )
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

	# Maxium time for new bids
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


	print("Do you wish to upload code for bid validation?")
	choice = input("[y/N/manual] => ")
	choice = choice.upper()

	if(choice.startswith("Y")):
		plat = platform.system()
		try:
			# linux platform
			if(plat == "Linux"): subprocess.call(['xdg-open', 'security2018-p1g1/client/code.txt'])
			# mac platform
			elif(plat == "Darwin"): subprocess.call(['open', 'security2018-p1g1/client/code.txt'])
			# windows platform
			elif(plat == "Windows"): os.startfile('security2018-p1g1/client/code.txt')
			else:
				print("Please Edit Code To Upload on code.txt file.")
		except:
			print( colorize("ERROR: Unable to open code upload file.", 'red') )
			quit()

		input("Press any key when code is ready to upload...")
		with open('security2018-p1g1/client/code.txt', 'r') as f:
		    new_auction["CODE"] = [line.rstrip('\n') for line in f]

	elif(choice.startswith("M")):
		# TODO: print guide
		pass

	new_auction["ACTION"] = "CREATE"
	new_auction["NONCE"] = server_answer["NONCE"]
	new_auction = json.dumps(new_auction)

	# Signing and creating outter layer of JSON message
	logging.info("Singning Message To Send Server")
	signed_message = cc.sign( new_auction.encode('UTF-8') )
	outter_message = {"SIGNATURE": toBase64( signed_message ),
				      "MESSAGE" : new_auction,
					  "CERTIFICATE" : toBase64( cc.get_certificate_raw() ),
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
		logging.info("Auction Creating Was Succesful")
		print( colorize("Auction succesfully created!", 'pink') )
		input("Press any key to continue...")
	elif (server_answer["STATE"] == "NOT OK"):
		clean(lines=1)
		logging.info("Auction Creating Failed : " + server_answer["ERROR"] )
		print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
		input("Press any key to continue...")
	else:
		clean(lines=1)
		logging.info("Auction Creating Failed With Unexpected Error ")
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
	certificate = fromBase64( server_answer['CERTIFICATE'] )
	signature = fromBase64(server_answer['SIGNED_LIST'] )
	plain = fromBase64(server_answer['LIST'] )
	if not verify_server( certificate, plain, signature ):
		print( colorize('Server Validation Failed!', 'red') )
		quit()

	# TODO: rest of this
	pass

def make_bid(auction_id, hidden_identity = False, hidden_value = False):
	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Init values
	value = 0
	identity = cc.get_certificate_raw()

	# Ask for value to offer
	# TODO: go back/confirm value to offer
	while True:
		try:
			value = int(input("Value to offer (EUR) : "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			clean()
			continue
		else:
			if value >= 0:
				clean(True)
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	if (hidden_identity or hidden_value):
		logging.info("Auction Requires to Encrypt Values, Encrypting...")
		# TODO:
		# We still need to decide how to get the key from the manager, using static one for now
		# To think: should manager give IV too? And is it a good idea to store IV on the beggining of cipher text
		# This has a good thing, in order to decipher something, you need the key on manager and IV on repository
		cipher_key = b'1234567890123456'
		if( hidden_identity ): identity = encrypt(cipher_key, str(identity))
		if( hidden_value ): value = encrypt(cipher_key, str(value))

	# Ask for CryptoPuzzle
	crypto_puzzle_request = {
								"ACTION" : "CRYPTOPUZZLE",
								"CERTIFICATE" : toBase64( identity )
							}

	# Send CryptoPuzzle Request
	logging.info("Sending CryptoPuzzle request to Repository")
	sock_repository.send( json.dumps(crypto_puzzle_request).encode("UTF-8") )
	# Waiting for server response
	server_answer = json.loads( wait_for_answer(sock_repository) )
	logging.info("Received CryptoPuzzle: " + json.dumps(server_answer))

	'''
		EXPECTED ANSWER:
			{
				"MESSAGE" : {
								"PUZZLE" : ____,
								"STARTS_WITH" : ____,
								"ENDS_WITH" : ____
							}
				"SIGNATURE" :  _____  (OF MESSAGE),
				"CERTIFICATE" : _____
			}
	'''

	# Verify server certificate, verify signature message
	certificate = fromBase64( server_answer['CERTIFICATE'] )
	message = fromBase64(server_answer['MESSAGE'] )
	signature = fromBase64(server_answer['SIGNATURE'] )
	logging.info("Verifying certificate and server signature of message")

	if not verify_server( certificate, message, signature ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	logging.info("Solving CryptoPuzzle...")
	solution = CryptoPuzzle.solve_puzzle(message["PUZZLE"], identity, \
				message["STARTS_WITH"] , message["ENDS_WITH"])

	bid = 	{
				"AUCTION" 		: auction_id,
				"VALUE"			: toBase64(value),
				"CERTIFICATE"	: toBase64(identity),
				"SOLUTION"		: toBase64(solution),
			}

	logging.info("Signing Bid...")
	signed_bid = cc.sign( bid.encode('UTF-8') )
	message = 	{
					"ACTION" : "OFFER",
					"MESSAGE" : bid,
					"SIGNATURE" : toBase64(signed_bid)
				}

	# Send Offer
	logging.info("Sending Bid To Repository")
	sock_repository.send( json.dumps(message).encode("UTF-8") )
	# Waiting for server response
	server_answer = json.loads( wait_for_answer(sock_repository) )
	logging.info("Received Answer From Server: " + json.dumps(server_answer))

	# TODO: what will receive? receipt etc...

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
		ascii = open('security2018-p1g1/common/ascii', 'r')					# Reading the sick ascii art
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
