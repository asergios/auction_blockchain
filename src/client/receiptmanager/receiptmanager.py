# coding: utf-8
from ...common.cryptmanager import *
from ..util import *
from Crypto.Hash import SHA256
from hmac import compare_digest
import hashlib
import os
import getpass
import sys

class ReceiptManager:

	def save_receipt(self, auction_id, bid_id, receipt, salt):
		'''
			Save Encrypted Receipt
		'''
		self.has_writting_perm()
		file = open('src/client/receiptmanager/receipts/'+auction_id+"_"+bid_id, 'wb')

		pw = self.get_password(salt)
		hmac = SHA256.new(receipt)
		hmac = hmac.digest()

		result = encrypt(pw, (hmac+receipt))
		file.write(result)

	def get_receipt(self, auction_id, bid_id, salt):
		'''
			Get Decrypted Receipt
		'''
		self.has_reading_perm()
		file = open('src/client/receiptmanager/receipts/'+auction_id+"_"+bid_id, 'rb')

		pw = getpass.getpass("Password: ", sys.stdout)
		pw = self.password_builder(pw, salt)
		result = decrypt(pw, file.read())
		if compare_digest(result[:32], SHA256.new(result[32:]).digest() ):
			return result[32:]
		return False

	def get_password(self, salt):
		'''
			Getting new password from user
		'''
		# Getting Password From User
		while True:
			pw = getpass.getpass("Please pick a password (minimum 6 character): ", sys.stdout)
			if(len(pw) >= 6):
				clean(True)
				clean(lines=1)
				repeat = getpass.getpass("Repeat Password: ", sys.stdout)
				if(pw == repeat):
					clean(True)
					break
				else:
					print( colorize('Passwords must match!', 'red') )
					clean()
			else:
				print( colorize('Password must be at least 6 characters!', 'red') )
				clean()

		return self.password_builder(pw,salt)


	def password_builder(self, password, salt):
		'''
			Hashing of Password
		'''
		password_hash = hashlib.pbkdf2_hmac('sha256', bytearray(password,'UTF-8'), b'\x00', 1000, 16)
		return password_hash

	def has_reading_perm(self):
		'''
			Checks read permissions
		'''
		while(not os.access('src/client/receiptmanager/receipts', os.R_OK)):
			print( colorize("I have no permissions to read your receipt, please give read permissions at src/client/receiptmanager/receipts", 'red') )
			input("Press any key to try again...")
			clean(lines = 2)

	def has_writting_perm(self):
		'''
			Checks writting permissions
		'''
		while(not os.access('src/client/receiptmanager/receipts', os.W_OK)):
			print( colorize("I have no permissions to save your receipt, please give write permissions at src/client/receiptmanager/receipts", 'red') )
			input("Press any key to try again...")
			clean(lines = 2)
