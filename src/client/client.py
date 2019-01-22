import os
import socket
import json
import base64
import sys
import platform
import subprocess
import hashlib
import getpass
from multiprocessing import Process
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
auction_list = []


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
	sock.settimeout(3)
	while True:
		try:
			data, addr = sock.recvfrom(4096)
			if data:
				logging.error(data)
				answer = json.loads(data.decode('UTF-8'))
				if(answer["ACTION"] == action):
					return answer
				else:
					logging.error("Server sent an Invalid JSON!: " + data)
		except:
			logging.error("Failed to connect to server or server sent an invalid JSON!")
			return False

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
		print(colorize('Who Hides The Information: \n 	1 - Client (Bid Validation Processed At The End Of Auction) \n 	2 - Manager (Bid Validation Processed When Sent)', 'green'))
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
			new_auction['AUCTION_EXPIRES'] = actual_timestamp() + int(input("Expiration time for Auction (hours): ")) * 60 * 60
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
			new_auction['BID_LIMIT'] = actual_timestamp() + int(input("Time extended for new bids (minutes): ")) * 60
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
	# If get information about a particular auction
	if auction_id:
		request["AUCTION_ID"] = auction_id

	# Nonce for server
	nonce = os.urandom(64)
	request["NONCE"] = toBase64(nonce)
	# Covert to JSON string
	request = json.dumps(request)
	# Send request to repository
	sock_repository.send(request.encode("UTF-8"))
	# Waiting for server response
	server_answer = wait_for_answer(sock_repository, auction_type+"_REPLY")
	if not server_answer: return

	'''
		Expected answer

		IF AUCTION_ID NOT GIVEN:
		{
			'CERTIFICATE' : ____,
			'SIGNATURE' : ____, (of 'MESSAGE')
			'MESSAGE' : {
							"NONCE" : ____,
							"LIST" : [{'TITLE':__, 'AUCTION_ID':___},{'TITLE':__, 'AUCTION_ID':___},...],
						}
		}

		IF GIVEN AUCTION_ID:
		{
			'CERTIFICATE' : ____,
			'SIGNATURE' : ____, (of 'MESSAGE')
			'MESSAGE' : {
							"NONCE" : ____,
							"AUCTION" : {
											"AUCTION_ID" : ____,
											"TITLE" : _____,
											"DESCRIPTION" : _____,
											"TYPE" : _____,
											"SUBTYPE" : ____,
											"WHO_HIDES": ____,
											"ENDING_TIMESTAMP" : ____,
											"BIDS" : []
										}
						}
		}
	'''

	# Verify server certificate and verify signature of auction list
	challenge = json.dumps(server_answer['MESSAGE']).encode('UTF-8')
	if not verify_server(server_answer['CERTIFICATE'], challenge, server_answer['SIGNATURE'] ) \
		or not fromBase64(server_answer['MESSAGE']['NONCE']) == nonce:
		print( colorize('Server Validation Failed!', 'red') )
		input()
		return

	# In case of getting a list of auctions
	if not auction_id:
		auctions = []
		auction_list = server_answer['MESSAGE']['LIST']
		# test subject comment line above and verify_server to use it
		# auction_list = [{'TITLE': 'test', 'AUCTION_ID': 1},{'TITLE': 'test2', 'AUCTION_ID': 2}]

		# Build Titles Of Auctions To Be printed
		for auction in auction_list:
			auctions.append({auction["TITLE"] : (list_auction, (auction_type, auction["AUCTION_ID"])) })
		auctions.append({ "Exit" : None })

		# Print the menu
		print_menu(auctions)

	# In case of getting a particular auction
	else:
		# Printing Auction Information
		auction = server_answer['MESSAGE']['AUCTION']
		# test subject comment line above and verify_server to use it
		#auction = {"AUCTION_ID" : 1, "TITLE" : "Tomatoes", "DESCRIPTION" : "Tomatoes from my beautiful farm",
		#				"TYPE" : 1, "SUBTYPE" : 2, "WHO_HIDES": 1, "ENDING_TIMESTAMP" : 1548979200, "BIDS" : [] }

		# Translating Type/Subtype/WhoHide in order for user to understand
		auction["TYPE"] = "ENGLISH" if auction["TYPE"] == 1 else "BLIND"
		auction["SUBTYPE"] = "PUBLIC IDENTITY" if auction["SUBTYPE"] == 1 else "HIDDEN IDENTITY"
		auction["WHO_HIDES"] = "CLIENT" if auction["WHO_HIDES"] == 1 else "SERVER"

		# Building Infomation to print
		auction_info = []
		auction_info.append( colorize('TITLE:		', 'pink') + auction["TITLE"])
		auction_info.append( colorize('DESCRIPTION:	', 'pink') + auction["DESCRIPTION"] )
		auction_info.append( colorize('TYPE:		', 'pink') + auction["TYPE"] )
		auction_info.append( colorize('SUBTYPE:	', 'pink') + auction["SUBTYPE"] )
		auction_info.append( colorize('HIDDEN BY:	', 'pink') + auction["WHO_HIDES"] )
		auction_info.append( colorize('BIDS (NOT YET DEFINED):	', 'pink') + str(auction["BIDS"]) )
		auction_info.append( colorize('ENDS IN:	', 'pink') )
		auction_info.append( "======================================================" )

		# Bulding Menu With Options For The Client
		menu = []
		menu.append({"Make Offer" : (make_bid, (auction["AUCTION_ID"], \
					auction["TYPE"] == "ENGLISH", auction["SUBTYPE"] == "HIDDEN IDENTITY", \
					auction["WHO_HIDES"] == "CLIENT"))})
		menu.append({ "Exit" : None })

		# Print Menu
		print_menu(menu, auction_info, auction["ENDING_TIMESTAMP"])

def make_bid(arg):
	'''
		Creates new bid (offer) to a given auction (auction_id)

		Steps:
			1 - If there are values to be encrypted by client: encrypt them with generated key
				If there are values to be encrypted by manager: encrypt them with manager public key
			2 - Send Bid To Repository
			3 - Save Receipt

	'''

	# Reading arguments
	auction_id = arg[0]
	is_english = arg[1]
	hidden_identity = arg[2]
	client_hides = arg[3]

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

	# Preparing data
	print( colorize( "Preparing data, please wait...", 'pink' ) )
	logging.info("Auction Requires to Encrypt Values, Encrypting...")

	# Hiding needed values
	cipher_key = os.urandom(16)
	# If manager is hidding, import his certificate to encrypt cipher_key
	if (not client_hides):
		manager_cert = CertManager.get_cert_by_name('manager.crt')
		cm = CertManager(manager_cert)
		hidden_cipher_key = cm.encrypt(cipher_key)

	# Need to hide identity?
	if (hidden_identity):
		identity = encrypt(cipher_key, identity)
	# Need to hide value?
	if (is_english):
		value = encrypt(cipher_key, bytes([value]))

	# Ask for CryptoPuzzle
	crypto_puzzle_request = {
								"ACTION" : "CRYPTOPUZZLE",
								"PUBLIC_KEY" : toBase64(identity),
								"AUCTION_ID" : auction_id
							}

	# Send CryptoPuzzle Request
	logging.info("Sending CryptoPuzzle request to Repository")
	sock_repository.send( json.dumps(crypto_puzzle_request).encode("UTF-8") )
	# Waiting for server response
	'''
		DESCRIPTION:
			This message is to request a cryptopuzzle to the repository,
			not much to add about it, it gives a public_key to be used on the
			cryptopuzzle generation (function create_puzzle in CryptoPuzzle package)

		SENT MESSAGE:
		{
			"ACTION" : "CRYPTOPUZZLE",
			"PUBLIC_KEY" : _____,
			"AUCTION_ID" : ________
		}
		EXPECTED ANSWER:
		{
			"ACTION" : "CRYPTOPUZZLE_REPLY",
			"MESSAGE" : {
							"PUZZLE" : ____,			# These are the values that create_puzzle will return
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

	if not verify_server( server_answer['CERTIFICATE'], json.dumps(message).encode('UTF-8'), server_answer['SIGNATURE'] ):
		logging.warning("Server Verification Failed")
		print( colorize('Server Validation Failed!', 'red') )
		input("Press any key to continue...")
		return

	logging.info("Solving CryptoPuzzle...")
	solution = CryptoPuzzle().solve_puzzle(message["PUZZLE"], identity, \
				fromBase64(message["STARTS_WITH"]) , fromBase64(message["ENDS_WITH"]))

	bid = 	{
				"AUCTION" 		: auction_id,
				"VALUE"			: toBase64(value),
				"CERTIFICATE"	: toBase64(identity),
				"SOLUTION"		: toBase64(solution),
			}

	logging.info("Signing Bid...")
	signed_bid = cc.sign( json.dumps(bid).encode('UTF-8') )
	message = 	{
					"ACTION" : "OFFER",
					"MESSAGE" : bid,
					"SIGNATURE" : toBase64(signed_bid)
				}

	# Key encrypted with manager public_key so he can read identity/value
	if not client_hides:
		message["MANAGER_SECRET"] = toBase64(hidden_cipher_key)

	# Send Offer
	logging.info("Sending Bid To Repository")
	sock_repository.send( json.dumps(message).encode("UTF-8") )
	'''
		DESCRIPTION:
			Client solved the puzzle so it will now return the solution together
			with his offer. VALUE and CERTIFICATE may be encrypted depending of the
			properties of the auction. The key used in this encryption is given in
			MANAGER_SECRET in case the auction is set as "SERVER/MANAGER hides".
			Obviously, the key in manager secret is encrypted with manager's public key
			so that the repository cant know it.
			What to do after?
				1 - The repository will check the cryptopuzzle solution
				2 - In case of valid, send the bid to manager for validation
				3 - In case "MANAGER_SECRET" is available, use it decrypt "IDENTITY"/"VALUE" and validate bid and signature.
				4 - If valid, sign "MESSAGE" and "SIGNATURE" and send it to repository
				5 - Repository now stores the bid and signs on top of manager signature
				6 - Send the result to the client, as receipt.

		SENT MESSAGE:
		{
			"ACTION" : "OFFER",
			"MESSAGE" : {
							"AUCTION" 		: ______,
							"VALUE"			: ______, (may be encrypted)
							"CERTIFICATE"	: ______, (may be encrypted)
							"SOLUTION"		: ______,
						},
			"SIGNATURE" : ________,
			"MANAGER_SECRET" : ______ (Optional, present if manager is going to hide something)
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


def print_menu(menu, info_to_print = None, timestamp = None):
	'''
		Print menu to the user
	'''
	while True:
		os.system('clear')													# Clear the terminal
		ascii = open('src/common/ascii', 'r')								# Reading the sick ascii art
		print( colorize(ascii.read(), 'pink') )								# Printing the ascii art as pink
		ascii.close()
		print('\n')

		# Print info if there is any
		if info_to_print:
			for info in info_to_print:
				print(info)

		# Printing the menu together with the index
		for item in menu:
			print( str(menu.index(item) + 1) + " - " + list(item.keys())[0] )

		# Print Count Down For Auction
		if info_to_print:
			p = Process(target=print_timer, args=(timestamp,4))
			p.start()
			choice = input(">> ")
			p.terminate()
			sys.stdout.write("\033[4B")
		else:
			choice = input(">> ")

		try:																# Reading the choice
			if int(choice) <= 0 : raise ValueError
			if list(menu[int(choice) - 1].values())[0] == None: return
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
	print_menu(menu)


if __name__ == "__main__":
    main()
