# coding: utf-8

import os
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

# Check if a int port number is valid
# Valid is bigger than base port number
def check_port(port, base=1024):
    ivalue = int(port)
    if ivalue <= base:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return ivalue


# Load raw file from disk
# Used to load the keys pairs from the disk
def load_file_raw(path):
    with open(path, 'rb') as f: content = f.read()
    return content


# classe para gerir as ligações dos multiplos clientes
class OpenConnections:
    def __init__(self):
        self.nonce = os.urandom(16)
        self.openConns = {}

    def add(self, data):
        self.openConns[self.nonce] = (data)
        rv = self.nonce
        self.nonce = os.urandom(16)
        return rv

    def value(self, key):
    	return self.openConns.get(key, None)

    def pop(self, nonce):
        return self.openConns.pop(nonce, None)
