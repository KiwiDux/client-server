import socket
import os
import time
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from datetime import datetime


#---------------------------------------------------------
# Decrypt the AES key with the server's private RSA key
#---------------------------------------------------------
def aes_key_decryption(private_key, aes_key_encrypted):
	rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgorithm=SHA512)
	aes_decrypt_key = rsa_cipher.decrypt(aes_key_encrypted)
	return aes_decrypt_key


#---------------------------------------------------------
# Decrypt the file using AES
#---------------------------------------------------------
def aes_file_decryption(aes_decrypt_key, encrypted_file_data, tag, nonce):
	aes_decrypt_cipher = AES.new(aes_decrypt_key, AES.MODE_GCM, nonce=nonce)
	decrypted_file_data = aes_decrypt_cipher.decrypt_and_verify(encrypted_file_data, tag)
	return decrypted_file_data


#---------------------------------------------------------
# Encrypt the AES key with RSA (SHA-512) (stored file)
#---------------------------------------------------------
def aes_key_encryption(public_key, aes_encrypt_key):
	rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
	key_encrypted = rsa_cipher.encrypt(aes_encrypt_key)
	return key_encrypted

#---------------------------------------------------------
# Encrypt recieved log file with AES-256-GCM (stored file)
#---------------------------------------------------------
def aes_file_encryption(key_encrypted, file_data):
	aes_encrypt_cipher = AES.new(key_encrypted, AES.MODE_GCM)  # GCM uses a nonce
	ciphertext, tag = aes_encrypt_cipher.encrypt_and_digest(file_data)
	return ciphertext, tag, aes_encrypt_cipher.nonce


#---------------------------------------------------------
# Verify the signature with the client's public key
#---------------------------------------------------------
def sig_verification(public_key, file_data, sig):
	hashed_object = SHA512.new(file_data)
	the_verifier = PKCS1_v1_5.new(public_key)
	return the_verifier.verify(hashed_object, sig)


#---------------------------------------------------------
# Receive log file
#---------------------------------------------------------
def receive_log_file(connection):
	private_key = file('server_private_key.pem')
	# Receive the encrypted AES key
	aes_key_encrypted = connection.recv(256)  # RSA-encrypted AES key
	aes_key = aes_key_decryption(private_key, aes_key_encrypted)

	# Receive the length of the encrypted file data
	file_size = int.from_bytes(connection.recv(4), byteorder='big')

	# Receive the encrypted file data
	encrypted_file_data = b''
	while len(encrypted_file_data) < file_size:
		encrypted_file_data += connection.recv(file_size - len(encrypted_file_data))

	# Receive the AES tag, nonce, and signature
	tag = connection.recv(16)  # AES-GCM tag
	nonce = connection.recv(16)  # AES-GCM nonce (must be 16 bytes)
	sig = connection.recv(256)  # RSA signature

	# Decrypt the file using the decrypted AES key
	try:
		decrypted_file_data = aes_file_decryption(aes_key, encrypted_file_data, tag, nonce)
	except ValueError as e:
		print('Decryption failed:', e)
		return None

	# Save the decrypted file
	with open('received_file.txt', 'wb') as file:
		file.write(decrypted_file_data)

	# Load the client's public key to verify the signature
	with open('client_public_key.pem', 'rb') as key_file:
		client_public_key = RSA.import_key(key_file.read())

	# Verify the signature
	if sig_verification(client_public_key, decrypted_file_data, sig):
		print('Signature is valid.')
	else:
		print('Signature is invalid.')

	return decrypted_file_data


####################################################################################################
#---------------------------------------------------------
# Store log report securely (as an encrypted file) 
#---------------------------------------------------------

# AES-256 key must be 32 bytes long
#aes_key = os.urandom(32) # Randomly generate a key (securely store this in practice)

def encrypt_logs(decrypted_file_data):
	if not decrypted_file_data:
		return None

	# Load the server's private key to sign the file
	with open('server_private_key.pem', 'rb') as key_file:
		private_key = RSA.import_key(key_file.read())
	
	# Load the client's public key to encrypt the AES key###
	with open('client_public_key.pem', 'rb') as key_file:
		client_public_key = RSA.import_key(key_file.read())

	# Combine all log data into one byte stream
	# Format: [Filename Length (4 bytes)][Filename][Content Length (4 bytes)][Content]
	
	file_data = b''.join('\nSTART OF {filename}\n'.encode('utf-8')(content for filename, content in decrypted_file_data))

    # Sign the file
	sig = sig_verification(private_key, file_data)
	hashed_object = SHA512.new(file_data)
	signpkcs = PKCS1_v1_5.new(private_key)
	sig = signpkcs.sign(hashed_object)
	print('File signed successfully.')

	# Generate a random AES key for symmetric encryption
	aes_key = get_random_bytes(32)  # AES-256
	print('AES key generated.')
	
	# Encrypt the file with AES-256-GCM
	encrypted_file_data, tag, nonce = aes_file_encryption(aes_key, file_data)
	print('File encrypted with AES.')

	# Encrypt the AES key with RSA (client's public key)
	encrypted_aes_key = aes_key_encryption(client_public_key, aes_key)
	print('AES key encrypted with RSA.')

	return encrypted_aes_key, encrypted_file_data, tag, nonce, sig

def save_log_file(encryption_result):
	save_folder = 'C:/LOGFILES/'
	current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
	filename = os.path.join(save_folder, current_time + ".txt")
	log_file = open(filename, "x") 
	with open(filename, "a") as log_file:
		log_file.write(encryption_result)
	log_file.close()


####################################################################################################


def start_server():
	server_ip_input = input("Enter the server IP address: ")
	server_port_input = input("Enter the server port: ")
	server_ip = server_ip_input
	server_port = int(server_port_input)
	#server_ip = '127.0.0.1'
	#server_port = 12345

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.bind((server_ip, server_port))  # Bind to any interface
	server_socket.listen(1)
	print('Server is listening on port', server_port)
	connection, address = server_socket.accept()
	print('Connection from', (address))
	print('Connection established at', datetime.now())

	# Receive the encrypted AES key
	aes_key_encrypted = connection.recv(256)  # RSA-encrypted AES key
	print('Encrypted AES key received.', (aes_key_encrypted))

	# Receive the length of the encrypted file data
	file_size = int.from_bytes(connection.recv(4), byteorder='big')

	# Receive the encrypted file data
	encrypted_file_data = b''
	while len(encrypted_file_data) < file_size:
		encrypted_file_data += connection.recv(file_size - len(encrypted_file_data))
	print('Encrypted file data received:', (encrypted_file_data))

	# Receive the AES tag, nonce, and signature
	tag = connection.recv(16)  # AES-GCM tag
	print('Tag:', (tag))
	nonce = connection.recv(16)  # AES-GCM nonce (must be 16 bytes)
	print('Nonce:', (nonce))
	sig = connection.recv(256)  # RSA signature
	print('Signature received.', (sig))

	# Load the server's private key to decrypt the AES key
	with open('server_private_key.pem', 'rb') as key_file:
		private_key = RSA.import_key(key_file.read())

	# Decrypt the AES key
	aes_key = aes_key_decryption(private_key, aes_key_encrypted)
	print('AES key decrypted.', (aes_key))

	# Decrypt the file using the decrypted AES key
	try:
		decrypted_file_data = aes_file_decryption(aes_key, encrypted_file_data, tag, nonce)
		print('File decrypted successfully.', (decrypted_file_data))
	except ValueError as e:
		print('Decryption failed: {e}', (e))
		connection.close()
		return

	# Save the decrypted file
	with open('received_file.txt', 'wb') as file:
		file.write(decrypted_file_data)
	print('File saved as ', 'received_file.txt')

	# Load the client's public key to verify the signature
	with open('client_public_key.pem', 'rb') as key_file:
		client_public_key = RSA.import_key(key_file.read())

	# Verify the signature
	if sig_verification(client_public_key, decrypted_file_data, sig):
		print('Signature is valid.')
	else:
		print('Signature is invalid.')

	print('Connection closed at', datetime.now())
	connection.close()

	## Encrypt logs
	print('\nEncrypting Logs')
	encryption_result = encrypt_logs(decrypted_file_data)
	if encryption_result:
		encrypted_aes_key, encrypted_file_data, tag, nonce, sig = encryption_result
	else:
		print('\nEncryption failed.')

	## Save logs
	save_log_file(encryption_result)
	

if __name__ == '__main__':
	start_server()