import os

colors = {
		'blue': '\033[94m',
		'pink': '\033[95m',
		'green': '\033[92m',
		}

def colorize(string, color):
	if not color in colors: return string
	return colors[color] + string + '\033[0m'

def create_new_auction():
	'''
		Creates new auction via auction manager
	'''
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
		ascii = open('ascii', 'r')											# Reading the sick ascii art
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