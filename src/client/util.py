import sys
import base64

colors = {
		'blue': '\033[94m',
		'pink': '\033[95m',
		'green': '\033[92m',
		'red' : '\033[91m'
		}

def toBase64(content):
	'''
		Converts content to base64 in order to send to server
	'''
	return base64.urlsafe_b64encode(content).decode()

def fromBase64(base64string):
	'''
		Decodes base64 content received from server
	'''
	return base64.urlsafe_b64decode(base64string)

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
