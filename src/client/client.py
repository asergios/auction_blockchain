import os
import socket
import json
import base64
import sys
import platform
import subprocess
import hashlib
import getpass
from ..common.utils import *
from ..common.cartaodecidadao import CartaoDeCidadao
from ..common.receiptmanager import ReceiptManager
from ..common.certmanager import CertManager
from ..common.cryptopuzzle import CryptoPuzzle
from ..common.cryptmanager import *
from ..common.logger import initialize_logger

logging = initialize_logger('AC', "src/client")

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


def verify_server(certificate, message, signature):
	'''
		Verify Server Certificate and Signature
	'''

	certificate = fromBase64(certificate)
	signature = fromBase64(signature)
	cm = CertManager(cert = certificate)
	return  cm.verify_certificate() and cm.verify_signature( signature , message )

def wait_for_answer(sock, action):
	'''
		Waits for a response from server
	'''
	while True:
		try:
			data, addr = sock.recvfrom(4096)
			if data:
				answer = json.loads(data.decode('UTF-8'))
				if(answer["ACTION"] == action):
					return answer
				else:
					logging.error("Server sent an Invalid JSON!: " + data)
		except:
			logging.error("Failed to connect to server or server sent an invalid JSON!")

	print( colorize("Unable to connect with server, please try again later.", 'red') )
	input("Press any key to continue...")
	return False

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
			"SUBTYPE": ___,				# SubType of the auction, as if it hides the identity or not
			"AUCTION_EXPIRES": ___,		# Expiration of Auction is hours
			"BID_LIMIT": ___,			# Time limit for new bids
			"CODE": ___,				# Dynamic code that user wrote
			"NONCE": ___,				# NONCE given by the server
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
	server_answer = wait_for_answer(sock_manager , "CHALLENGE_REPLY")
	if not server_answer: return
	logging.info("Received Challenge Response: " + json.dumps(server_answer))

	# Verify server certificate, verify signature of challenge and decode NONCE
	logging.info("Verifying certificate and server signature of challenge")
	if not verify_server( server_answer['CERTIFICATE'], challenge, server_answer['CHALLENGE_RESPONSE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

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
		print(colorize('Types available: \n 	1 - English Auction (Public Values) \n 	2 - Blind Auction (Hidden Values Revealed at the end)', 'green'))
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

	# Auction SubType
	while True:
		if new_auction['TYPE'] == 1:
			# English Auction must have hidden identity
			new_auction['SUBTYPE'] = 2
			break
		print(colorize('SubTypes available: \n 	1 - Public Identity\n 	2 - Hidden identity [until end of auction]', 'green'))
		try:
			new_auction['SUBTYPE'] = int(input("SubType: "))
		except ValueError:
			print( colorize('SubType must be a number!', 'red') )
			clean(lines=5)
			continue
		else:
			if new_auction['SUBTYPE'] == 1 or new_auction['SUBTYPE'] == 2:
				clean(True)
				break
			else:
				print( colorize('Please pick one of the available subtypes.', 'red') )
				clean(lines=5)

	# Who hides the information
	while True:
		if new_auction['TYPE'] == 1:
			# English Auction identity must be hidden by manager
			new_auction['WHO_HIDES'] = 2
			break
		print(colorize('Who Hides The Information: \n 	1 - Client (Bid Validation Processed At The End Of Auction) \n 2 - Manager (Bid Validation Processed When Sent)', 'green'))
		try:
			new_auction['WHO_HIDES'] = int(input("Who Hides: "))
		except ValueError:
			print( colorize('Must be a number!', 'red') )
			clean(lines=5)
			continue
		else:
			if new_auction['WHO_HIDES'] == 1 or new_auction['WHO_HIDES'] == 2:
				clean(True)
				break
			else:
				print( colorize('Please pick one of the available options.', 'red') )
				clean(lines=5)

	# Time for Auction expiration (hours)
	while True:
		try:
			new_auction['AUCTION_EXPIRES'] = int(input("Expiration time for Auction (hours): "))
		except ValueError:
			print( colorize('Expiration must be a number!', 'red') )
			clean()
			continue
		else:
			if new_auction['AUCTION_EXPIRES'] >= 0:
				clean(True)
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	# Times That Auction Is Extended in case of new bids
	while True:
		try:
			new_auction['BID_LIMIT'] = int(input("Time extended for new bids (minutes): "))
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


	# Dynamic Code For Bid Validation
	print("Do you wish to upload code for bid validation?")
	choice = input("[y/N/manual] => ")
	choice = choice.upper()

	if(choice.startswith("Y")):
		plat = platform.system()
		try:
			# linux platform
			if(plat == "Linux"): subprocess.call(['xdg-open', 'src/client/code.txt'])
			# mac platform
			elif(plat == "Darwin"): subprocess.call(['open', 'src/client/code.txt'])
			# windows platform
			elif(plat == "Windows"): os.startfile('src/client/code.txt')
			else:
				print("Please Edit Code To Upload on code.txt file.")
		except:
			print( colorize("ERROR: Unable to open code upload file.", 'red') )
			quit()

		print("File for dynamic code will open sortly... please wait.")
		input("Press any key when code is ready to upload...")
		with open('src/client/code.txt', 'r') as f:
		    new_auction["CODE"] = [line.rstrip('\n') for line in f if not line.startswith("#")]

	elif(choice.startswith("M")):
		# TODO: print guide
		pass

	# Building INNER JSON
	new_auction["ACTION"] = "CREATE"
	new_auction["NONCE"] = server_answer["NONCE"]
	new_auction = json.dumps(new_auction)

	# Signing and creating OUTTER layer of JSON message
	logging.info("Signing Message To Send Server")
	signed_message = cc.sign( new_auction.encode('UTF-8') )
	outter_message = {"SIGNATURE": toBase64( signed_message ),
				      "MESSAGE" : new_auction,
					  "ACTION" : "CREATE" }

	# Sending New Auction Request For Auction Manager
	logging.info("Sending Request To Server:" + json.dumps(outter_message))
	sock_manager.send( json.dumps(outter_message).encode("UTF-8") )

	# Wait for Server Response
	logging.info("Waiting for server response")
	print( colorize( "Creating Auction, please wait...", 'pink' ) )
	server_answer = wait_for_answer(sock_manager, "CREATE_REPLY")
	if not server_answer: return
	logging.info("Received Server Response: " + json.dumps(server_answer))

	if (server_answer["STATE"] == "OK"):
		clean(lines=1)
		logging.info("Auction Creating Was Successful")
		print( colorize("Auction successfully created!", 'pink') )
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


def list_auction(arg):
	'''
		Requests auctions to auction repository

		JSON sent to Auction Repository Description:

		{
			"ACTION" : "ENGLISH/BLIND",
			"NONCE"  : _______________
			(Optional) "AUCTION_ID" : XX
		}
	'''

	auction_type = arg[0]
	auction_id = arg[1] if 1 < len(arg) else None

	request = {"ACTION" : auction_type}
	nonce = os.urandom(64)
	if auction_id:
		request["AUCTION_ID"] = auction_id

	request["NONCE"] = toBase64(nonce)
	# Covert to JSON string
	request = json.dumps(request)
	# Send request to repository
	sock_repository.send(request.encode("UTF-8"))
	# Waiting for server response
	server_answer = wait_for_answer(sock_repository, "ENGLISH_REPLY")
	if not server_answer: return

	'''
		I will be expecting an answer in this format:
		{
			"SIGNED_LIST": 		// Signed list of auctions
			"CERTIFICATE":		// Certificate of public key of the server
			"LIST":				// Raw List of Auctions
		}
	'''
	server_signed = nonce + json.dumps(server_answer['LIST']).encode('UTF-8')

	# Verify server certificate and verify signature of auction list
	if not verify_server( server_answer['CERTIFICATE'], server_signed, server_answer['SIGNED_LIST'] ):
		print( colorize('Server Validation Failed!', 'red') )
		quit()

	# TODO: rest of this

	# Sample for testing
	auctions = [
	    { "Ovos a Acabar o Prazo": (list_auction, (auction_type, 12) ) },
	    { "Carro": (list_auction, (auction_type, 13) ) },
	    { "Rare Pepe": (list_auction, (auction_type, 14) ) },
		{ "Exit" : (print_menu, menu) }
	]

	print(server_answer['LIST'])
	input("")
	pass

def make_bid(auction_id, hidden_identity = False, hidden_value = False):
	'''
		Creates new bid (offer) to a given auction (auction_id)

		Steps:
			1 - Key Agreement With Auction Manager to be used on ecrypted data
			2 - Send Bid To Repository
			3 - Save Receipt

		JSON sent to Auction Manager Description:


	'''
	# Scanning user CartaoDeCidadao
	logging.info("Reading User's Cartao De Cidadao")
	print( colorize( "Reading Citizen Card, please wait...", 'pink' ) )
	cc.scan()
	clean(lines = 1)

	# Init values for the bid (value to offer and identity of user)
	value = 0
	identity = cc.get_certificate_raw()

	# Ask user for value to offer
	while True:
		try:
			value = int(input("Value to offer (EUR) : "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			clean()
			continue
		else:
			if value >= 0:
				confirm = input("Are you sure? Bids are irreversible [y/N]: ").upper()
				if confirm.startswith("Y"):
					clean(True)
					break
				clean()
				continue
			else:
				print( colorize('Please pick a positive number.', 'red') )
				clean()

	# Establish connection with server (We are not actually doing that, is so that the user knows something is going on)
	print( colorize( "Establishing connection with server, please wait...", 'pink' ) )
	# If there is any value to be hidden, send key to manager
	if (hidden_identity or hidden_value):
		logging.info("Auction Requires to Encrypt Values, Encrypting...")
		# Challenger to send to manager
		challenge = os.urandom(64)
		key_init = {
						"ACTION" : "KEY_SET_INIT",
						"CHALLENGE" : toBase64( challenge ),
						"CERTIFICATE" : toBase64( cc.get_certificate_raw)
					  }
		# Sending Request
		logging.info("Sending Key Init Request to Manager")
		sock_manager.send( json.dumps(key_init).encode("UTF-8") )
		# Waiting for server response
		'''
			SENT MESSAGE:
			{
				"ACTION" : "KEY_SET_INIT",
				"CHALLENGE" : ________,
				"CERTIFICATE" : ________
			}
			EXPECTED ANSWER:
			{
				"ACTION" : "KEY_ANSWER",
				"CERTIFICATE": ______,
				"CHALLENGE_RESPONSE": _____,
				"NONCE":_____
			}
		'''
		server_answer = wait_for_answer(sock_manager, "KEY_ANSWER")
		if not server_answer: return
		logging.info("Received Key Init Answer From Server! : " + server_answer)

		# Verify server certificate, verify signature of challeng
		logging.info("Verifying certificate and server signature of challenge")
		if not verify_server( server_answer['CERTIFICATE'], challenge, server_answer['CHALLENGE_RESPONSE'] ):
			logging.warning("Server Verification Failed")
			print( colorize('Server Validation Failed!', 'red') )
			input("Press any key to continue...")
			return

		# Generate cipher_key and encrypt it with server public_key
		cipher_key = os.urandom(64)
		cm = CertManager(cert=fromBase64(server_answer['CERTIFICATE']))
		cipher_key_enc = cm.encrypt(cipher_key)

		# Building inner and outter json
		to_sign = {
					 "NONCE" : server_answer['NONCE'],
					 "KEY" : toBase64(cipher_key_enc),
					 "AUCTION": auction_id
				  }
		signature = cc.sign(to_sign.encode('UTF-8'))
		key_set = {
						"ACTION" : "KEY_SET",
						"MESSAGE" : to_sign,
						"SIGNATURE" : toBase64(signature)
					}

		# Sending Request
		logging.info("Sending Key Set Request to Manager")
		sock_manager.send( json.dumps(key_set).encode("UTF-8") )
		# Waiting for server response
		'''
			SENT MESSAGE:
			{
				"ACTION" : "KEY_SET",
				"MESSAGE" : {
								"NONCE": _____,
								"KEY": _______, (encrypted with manager's pubkey)
								"AUCTION": _____ (auction_id where key will be used)
							},
				"SIGNATURE" : ________
			}
			EXPECTED ANSWER:
			{
				"ACTION" : "KEY_ACK",
				"STATE": ______,
			}
		'''
		server_answer = wait_for_answer(sock_manager, "KEY_ACK")
		if not server_answer: return
		logging.info("Received Key Ack Answer From Server! : " + server_answer)

		if (server_answer["STATE"] == "NOT OK"):
			clean(lines=1)
			logging.info("Bid Creating Failed : " + server_answer["ERROR"] )
			print( colorize("ERROR: " + server_answer["ERROR"], 'red') )
			input("Press any key to continue...")
			return

		if( hidden_identity ): identity = encrypt(cipher_key, str(identity))
		if( hidden_value ): value = encrypt(cipher_key, str(value))

	# Ask for CryptoPuzzle
	crypto_puzzle_request = {
								"ACTION" : "BID_INIT",
								"CERTIFICATE" : toBase64( identity ),
								"AUCTION_ID" : auction_id
							}

	# Send CryptoPuzzle Request
	logging.info("Sending CryptoPuzzle request to Repository")
	sock_repository.send( json.dumps(crypto_puzzle_request).encode("UTF-8") )
	# Waiting for server response
	'''
		SENT MESSAGE:
		{
			"ACTION" : "BID_INIT",
			"CERTIFICATE" : _____, (encrypted, validate with manager)
			"AUCTION_ID" : ________
		}
		EXPECTED ANSWER:
		{
			"ACTION" : "CRYPTOPUZZLE_REPLY",
			"MESSAGE" : {
							"PUZZLE" : ____,
							"STARTS_WITH" : ____,
							"ENDS_WITH" : ____,
						}
			"SIGNATURE" :  _____  (OF MESSAGE),
			"CERTIFICATE" : _____
		}
	'''
	server_answer = wait_for_answer(sock_repository, "CRYPTOPUZZLE_REPLY")
	if not server_answer: return
	logging.info("Received CryptoPuzzle: " + json.dumps(server_answer))

	# Verify server certificate, verify signature message and challenge
	message = server_answer['MESSAGE']
	logging.info("Verifying certificate and server signature of message")

	if fromBase64(message["NONCE"]) != nonce or \
			not verify_server( server_answer['CERTIFICATE'], message, server_answer['SIGNATURE'] ):
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
	'''
		SENT MESSAGE:
		{
			"ACTION" : "BID_INIT",
			"MESSAGE" : {
							"AUCTION" 		: ______,
							"VALUE"			: ______, (may be encrypted)
							"CERTIFICATE"	: ______, (encrypted)
							"SOLUTION"		: ______,
						},
			"SIGNATURE" : ________
		}
		EXPECTED ANSWER:
		{
			"ACTION": "RECEIPT",
			"RECEIPT": ________
		}
	'''
	# Waiting for server response
	server_answer = wait_for_answer(sock_repository, "RECEIPT")
	if not server_answer: return
	logging.info("Received Answer From Server: " + json.dumps(server_answer))

	# TODO: what will receive? receipt etc...
	save_receipt("12345", "12345", "receipt")

	pass

def my_auctions():
	pass

def my_bids():
	pass


def print_menu(menu):
	'''
		Print menu to the user
	'''
	os.system('clear')													# Clear the terminal
	ascii = open('src/common/ascii', 'r')								# Reading the sick ascii art
	print( colorize(ascii.read(), 'pink') )								# Printing the ascii art as pink
	ascii.close()
	print('\n')
	for item in menu:													# Printing the menu together with the index
		print( str(menu.index(item) + 1) + " - " + list(item.keys())[0] )

	choice = input(">> ")

	try:																# Reading the choice
		if int(choice) <= 0 : raise ValueError
		if list(menu[int(choice) - 1].values())[0] == None: quit()
		list(menu[int(choice) - 1].values())[0][0](list(menu[int(choice) - 1].values())[0][1])
	except (ValueError, IndexError):
		pass

# Default Menu to be printed to the user
menu = [
    { "Create new auction": (create_new_auction, None) },
    { "List Open Auctions [English Auction]": (list_auction, ("ENGLISH", ) ) },
    { "List Open Auctions [Blind Auction]": (list_auction, ("BLIND", ) ) },
	{ "Owned Auctions": (my_auctions, None)},
	{ "Participated Auctions": (my_bids, None)},
	{ "Exit" : None }
]

def main():
	while True:
		print_menu(menu)


if __name__ == "__main__":
    main()
