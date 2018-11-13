import os
import socket
import json
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
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)	# Socket used for communication

def colorize(string, color):
	if not color in colors: return string
	return colors[color] + string + '\033[0m'

def create_new_auction():
	'''
		Creates new auction via auction manager

		JSON sent to Auction Manager Description:

		{
			"ACTION" : "CREATE",					# Action we intend auction manager to do, just for easier reading on server-side
			"TITLE": "_____",						# Title of the auction
			"DESCRIPTION": "_____",					# Description of the auction
			"TYPE": ___,							# Type of the auction 1 being english auction and 2 being blind auction
			"BID_LIMIT": ___,						# Limit of bids allowed per bidder, this value will be 0 if no limit is applied
			"ALLOWED_BIDDERS": [___, ___, ...]		# Allowed bidder to participate on this auction, the filter is done by the CC number
		}
	'''
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
			new_auction['BID_LIMIT'] = int(input("Limit of Bids per Bidder (0 for no limit): "))
		except ValueError:
			print( colorize('Limit must be a number!', 'red') )
			continue
		else:
			if new_auction['BID_LIMIT'] >= 0:
				break
			else:
				print( colorize('Please pick a positive number.', 'red') )
	
	# Auction Bidders Accepted
	while True:
		print(colorize('Do you wish to filter bidders that can play? [y/N]?', 'green'))
		choice = input(">> ")

		if(choice.upper() == "Y"):
			new_auction['ALLOWED_BIDDERS'] = []
			while True:
				try:
					cc_number = int( input("Insert CC of allowed bidder (0 to finish): ") )
				except ValueError:
					print( colorize('CC number must be a number!', 'red') )
					continue
				else:
					# TODO: more cc number validation
					if (cc_number == 0):
						break
					else:
						new_auction['ALLOWED_BIDDERS'].append(cc_number)
						print( colorize('Allowed Bidders:' + str(new_auction['ALLOWED_BIDDERS']),'green') )
			break

		elif(choice.upper() == "N" or choice == ""):
			break

	new_auction["ACTION"] = "CREATE"
	sock.sendto(str(json.dumps(new_auction)).encode("UTF-8"), (UDP_IP, UDP_PORT_MANAGER))	# Sending New Auction Request For Auction Manager TODO: do we assume he received?

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