# coding: utf-8
from ...common.cryptmanager import *
from ..util import *
from ..cartaodecidadao import CartaoDeCidadao
from Crypto.Hash import SHA256
from hmac import compare_digest
import hashlib
import os
import getpass
import sys

class ReceiptManager:

	def __init__(self, cc):
		self.cc = cc
		self.cc_number = self.cc.get_identity()[1]

	def save_receipt(self, auction_id, receipt):
		'''
			Save Receipt
		'''
		# Checking for Permissions on Folder
		self.check_perm()
		# Checking existence of user dir
		self.check_dir()

		# Opening File Where Receipt Will Be Stored
		file = open('src/client/receiptmanager/receipts/'+self.cc_number+'/'+auction_id, 'wb')
		# Getting User Password Key
		pw = self.get_key()
		# Building HMAC for receipt
		hmac = SHA256.new(receipt)
		hmac = hmac.digest()
		# Encrypting receipt with key
		result = encrypt(pw, (hmac+receipt))
		# Writting on File
		file.write(result)
		file.close()

	def get_receipt(self, auction_id, pw = None):
		'''
			Get Receipt
		'''
		# Checking for Permissions on Folder
		self.check_perm()
		# Checking existence of user dir
		self.check_dir()

		# Checking if such receipt exists
		if os.path.isfile('src/client/receiptmanager/receipts/'+self.cc_number+'/'+auction_id):
			# Opening receipt file
			file = open('src/client/receiptmanager/receipts/'+self.cc_number+'/'+auction_id, 'rb')
			# Getting the key
			if not pw:
				pw = self.get_key()
			# Decrypting Receipt
			result = decrypt(pw, file.read())
			file.close()

			# Checking integrity of the receipt
			if(compare_digest(result[:32], SHA256.new(result[32:]).digest())):
				return result[32:]
			else:
				print( colorize("ERROR: Corrupted File Or Unauthorized Access", 'red') )
				input("Press any key to continue...")
				return None
		else:
			print( colorize("ERROR: Receipt Not Found", 'red') )
			input("Press any key to continue...")
			return None

	def get_receipts(self):
		'''
			Get All Receipts
		'''
		# Checking for Permissions on Folder
		self.check_perm()
		# Checking existence of user dir
		self.check_dir()
		# Getting the key
		pw = self.get_key()

		receipts = []
		# For Each Receipt
		for filename in os.listdir('src/client/receiptmanager/receipts/'+self.cc_number):
			# Ignore pwd file
			if filename.startswith('.'): continue
			# Add receipt to receipts list
			receipts.append(self.get_receipt(filename, pw))

		return receipts


	def get_key(self):
		'''
			Getting new password from user
		'''
		# Checking if there is a password already set
		if os.path.isfile("src/client/receiptmanager/receipts/"+self.cc_number+"/.pwd"):
			# Getting .pwd contents and sign it
			file = open("src/client/receiptmanager/receipts/"+self.cc_number+"/.pwd", "rb")
			key = self.cc.sign(file.read())
			file.close()
		else:
			# Building new random for password
			new = os.urandom(128)
			file = open("src/client/receiptmanager/receipts/"+self.cc_number+"/.pwd", "wb")
			file.write(new)
			file.close()
			key = self.cc.sign(new)

		# Return Hashing Of Password
		return self.password_builder(key, self.cc.get_public_key()[10:26])

	def password_builder(self, password, salt):
		'''
			Hashing of Password
		'''
		password_hash = hashlib.pbkdf2_hmac('sha256', password, salt, 1000, 16)
		return password_hash

	def check_dir(self):
		'''
			Check if DIR exists, if it doesn't, create a new one
		'''
		if os.path.isdir("src/client/receiptmanager/receipts/"+self.cc_number): return
		else: os.mkdir("src/client/receiptmanager/receipts/"+self.cc_number)

	def check_perm(self):
		'''
			Checks read and write permissions
		'''
		while(not os.access('src/client/receiptmanager/receipts', os.R_OK)):
			print( colorize("I have no READ permissions, please allow READ permissions at src/client/receiptmanager/receipts", 'red') )
			input("Press any key to try again...")
			clean(lines = 2)

		while(not os.access('src/client/receiptmanager/receipts', os.W_OK)):
			print( colorize("I have no WRITE permissions, please allow WRITE permissions at src/client/receiptmanager/receipts", 'red') )
			input("Press any key to try again...")
			clean(lines = 2)
