import hashlib
import os
from Crypto.Cipher import AES

def encrypt(pwd, message):
	# Convert message to bytearray
	#message = bytearray(message, 'UTF-8')
	# Generate IV
	iv = os.urandom(AES.block_size)
	# Create Cipher Engine (CBC)
	cipher_engine = AES.new(pwd, AES.MODE_CBC, iv)

	# Divide message in blocks
	parts = [message[i:i + AES.block_size] for i in range(0, len(message), AES.block_size)]
	# Addind IV to beggining of cipher
	ciphertext = iv

	# Encrypt blocks
	for part in parts:
		# Add padding on last block
		if len(part) % AES.block_size != 0:
			ciphertext += cipher_engine.encrypt( pad(part, AES.block_size) )
		else:
			ciphertext += cipher_engine.encrypt( part )

	# Return Encypted Message
	return ciphertext

def decrypt(pwd, cipher):
	# Divide message in blocks
	parts = [cipher[i:i + AES.block_size] for i in range(0, len(cipher), AES.block_size)]

	# Create Cipher Engine (CBC)
	c = AES.new(pwd, AES.MODE_CBC, parts[0])
	plaintext = b''

	# Decrypt each block starting at the second (first one is IV)
	for part in parts[1:-1]:
		plaintext += c.decrypt(part)

	# Remove padding from last block
	tmp = c.decrypt(parts[-1])
	plaintext += tmp[:-tmp[-1]]

	# Return PlainText
	return plaintext


def pad(data, bLen):
	# Adds padding to block
	return data + bytearray((bLen - len(data) % bLen) * chr(bLen - len(data) % bLen),'UTF-8')
