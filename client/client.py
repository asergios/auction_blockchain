import os
import socket
import json
import base64
from ..cartaodecidadao import CartaoDeCidadao


colors = {
		'blue': '\033[94m',
		'pink': '\033[95m',
		'green': '\033[92m',
		'red' : '\033[91m'
		}

UDP_IP = "127.0.0.1"									# Assuming the servers will be local
UDP_PORT_MANAGER = 5001									# Port used for communication with auction manager
UDP_PORT_REPOSITORY = 5002								# Port used for communication with auction repository

sock_manager = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# Socket used for communication with manager
sock_manager.connect((UDP_IP, UDP_PORT_MANAGER))

sock_repository = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# Socket used for communication with repository
sock_repository.connect((UDP_IP, UDP_PORT_REPOSITORY))

cc = CartaoDeCidadao()


def colorize(string, color):
	if not color in colors: return string
	return colors[color] + string + '\033[0m'

def wait_for_answer(sock):
	while True:
		try:
			data, addr = sock.recvfrom(1024)
			if data:
				return data
		except:
			print( colorize("Unable to connect with server, please try again later.", 'red') )
			quit()

def create_new_auction():
	'''
		Creates new auction via auction manager

		JSON sent to Auction Manager Description:

		{
			"ACTION" : "CREATE",					# Action we intend auction manager to do, just for easier reading on server-side
			"TITLE": "_____",						# Title of the auction
			"DESCRIPTION": "_____",					# Description of the auction
			"TYPE": ___,							# Type of the auction 1 being english auction and 2 being blind auction
			"BID_LIMIT": ___,						# Time limit for new bids
		}
	'''
	# Scanning user CartaoDeCidadao
	cc.scan()

	# Establish connection with server
	print( colorize( "Establishing connection with server, please wait...", 'pink' ) )
	challenge = os.urandom(64)
	connection = {"CHALLENGE": base64.urlsafe_b64encode( challenge ).decode() ,\
	 			  "CERTIFICATE": base64.urlsafe_b64encode( cc.get_certificate_raw() ).decode() }
	connection = json.dumps(connection)
	sock_manager.send( json.dumps(connection).encode() )
	server_answer = json.loads( wait_for_answer(sock_manager) )

	'''
		I will be expecting an answer in this format:
		{
			"CHALLENGE_RESPONSE": // Signed challenge with server private key
			"CERTIFICATE":		 // Certificate of public key of the server
			"NONCE":			// random nonce, 128 bits should be ideal | os.urandom(128)
		}
		// I am expecting everything to be encoded with base64.urlsafe_b64encode( {<content>} ).decode()
	'''

	# Verify server certificate, verify signature of challenge and decode NONCE
	cc.verify_certificate( base64.urlsafe_b64decode( server_answer['CERTIFICATE'].encode() ) )
	cc.verify_signature( base64.urlsafe_b64decode(server_answer['CHALLENGE_RESPONSE'].encode() ), challenge )
	server_answer["NONCE"] = base64.urlsafe_b64decode( server_answer["NONCE"].encode() )

	new_auction = {}

	# Auction Title
	while True:
		new_auction["TITLE"] = input("Title: ")
		if new_auction['TITLE'] != "":
			break
		else:
			print( colorize('Title can\'t be empty!', 'red') )

	# Auction Description
	while True:
		new_auction['DESCRIPTION'] = input("Description: ")
		if new_auction['DESCRIPTION'] != "":
			break
		else:
			print( colorize('Description can\'t be empty!', 'red') )

	# Auction Type
	while True:
		print(colorize('Types available: \n 	1 - English Auction \n 	2 - Blind Auction', 'green'))
		try:
			new_auction['TYPE'] = int(input("Type: "))
		except ValueError:
			print( colorize('Type must be a number!', 'red') )
			continue
		else:
			if new_auction['TYPE'] == 1 or new_auction['TYPE'] == 2:
				break
			else:
				print( colorize('Please pick one of the available types.', 'red') )

	# Auction bids limit per bidder
	while True:
		try:
			new_auction['BID_LIMIT'] = int(input("Limit time for new bids (minutes): "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			continue
		else:
			if new_auction['BID_LIMIT'] >= 0:
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )

	new_auction["ACTION"] = "CREATE"
	new_auction["NONCE"] = server_answer["NONCE"]

	# Covert to JSON string
	new_auction = json.dumps(new_auction)

	# Signing and creating outter layer of JSON message
	signed_message = cc.sign( new_auction )
	outter_message = {"SIGNATURE": base64.urlsafe_b64encode( signed_message ).decode(),
				      "MESSAGE" : new_auction,
					  "NONCE" : server_answer["NONCE"] }

	sock_manager.send( json.dumps(outter_message).encode() )	# Sending New Auction Request For Auction Manager

	print( colorize("Auction succesfully created!", 'pink') )
	input("Press any key to continue...")
	pass

def list_english_auction():
	'''
		Requests english auctions to auction repository
	'''
	pass

def list_blind_auction():
	'''
		Requests blind auctions to auction repository
	'''
	pass


# Menu to be printed to the user
menu = [
    { "Create new auction": create_new_auction },
    { "List open auctions [English Auction]": list_english_auction },
    { "List open auctions [Blind Auction]": list_blind_auction },
    { "Exit": exit },
]

def main():
	while True:
		os.system('clear')													# Clear the terminal
		ascii = open('security2018-p1g1/common/ascii', 'r')											# Reading the sick ascii art
		print( colorize(ascii.read(), 'pink') )								# Printing the ascii art as pink
		ascii.close()
		print('\n')
		for item in menu:													# Printing the menu together with the index
			print( str(menu.index(item) + 1) + " - " + list(item.keys())[0] )

		choice = input(">> ")

		try:																# Reading the choice
			if int(choice) <= 0 : raise ValueError
			list(menu[int(choice) - 1].values())[0]()
		except (ValueError, IndexError):
			pass

if __name__ == "__main__":
    main()
