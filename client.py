import socket
import os
import logging
import time
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from logging.handlers import RotatingFileHandler
from sys import stdout
from datetime import datetime

#---------------------------------------------------------
# Check List
# Double check all these are correct
#---------------------------------------------------------
# AES-256 (32-byte key)
# RSA-2048 for key exchange
# SHA-512 for digital signatures
# Integrity verification (SHA-512)
# Digital signature on each log file
# Hybrid encryption (AES for data, RSA for key)
# AES-GCM for authenticated encryption
# Manual send option


#---------------------------------------------------------
# Partially done
#---------------------------------------------------------
# Secure storage of private key
# Secure transport channel	End-to-End but there is no TLS for socket protection
# Automated daily scheduled logging
# Automatic log file scanning


#---------------------------------------------------------
# Not Done
#---------------------------------------------------------
# PKI, certificate-based public key management
# Periodic key changes (rotation)
# Automated daily scheduled sending
# Structured communication protocol
# Log report metadata (timestamp, hostname, file name)
# Secure server IP discovery


#---------------------------------------------------------
# Clear Screen
#---------------------------------------------------------
def clear_screen():
    os.system('cls')


#---------------------------------------------------------
# Digital Signature (SHA-512, RSA)
#---------------------------------------------------------
def file_signature(private_key, file_data):
	hashed_object = SHA512.new(file_data)
	signpkcs = PKCS1_v1_5.new(private_key)
	sig = signpkcs.sign(hashed_object)
	return sig


#---------------------------------------------------------
# Encrypt the AES key with RSA (SHA-512)
#---------------------------------------------------------
def aes_key_encryption(public_key, aes_key):
	rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
	key_encrypted = rsa_cipher.encrypt(aes_key)
	return key_encrypted


#---------------------------------------------------------
# Encrypt the file with AES-256-GCM
#---------------------------------------------------------
def aes_file_encryption(aes_key, file_data):
	aes_cipher = AES.new(aes_key, AES.MODE_GCM)  # GCM uses a nonce
	ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
	return ciphertext, tag, aes_cipher.nonce


#---------------------------------------------------------
# Logging schedule
#---------------------------------------------------------
def generate_logs():
	log_dir = 'LOGS'
	# create directory if needed
	os.makedirs(log_dir, exist_ok=True)

	# create timestamp variable for filenames
	timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
	number = 0
	# build filename as a string, not a tuple
	logname = timestamp + '.txt'
	filepath = os.path.join(log_dir, logname)

	# if the filename already exists, add number suffix to the filename
	while os.path.exists(filepath):
		number += 1
		logname = timestamp + '_' + str(number) + '.txt'
		filepath = os.path.join(log_dir, logname)

	# configure logging to write to the chosen file
	try:
		logging.basicConfig(
			filename=filepath,
			filemode='w',
			level=logging.INFO,
			format='%(asctime)s - %(levelname)s - %(message)s'
		)
		open(filepath, 'a').close()
	except PermissionError:
		print('Error: Unable to create log file')
		return None
	
	print('Logs generated: ', filepath)
	return filepath


#---------------------------------------------------------
# Log Directory scan and collection
#---------------------------------------------------------
def log_gather(filepath):
	log_data_list = []
	old_log_list = []
	log_list = []
	
	tracking_file = 'processed_logs.txt'

	# Ensure LOGS directory exists
	if not os.path.exists('LOGS'):
		print('Directory ', 'LOGS', ' not found.')
		return log_data_list

	# Get current list of files in LOGS
	current_logs = [file for file in os.listdir('LOGS') if os.path.isfile(os.path.join('LOGS', file))]

	# Check previously known logs
	if os.path.exists(tracking_file):
		with open(tracking_file, 'r') as file:
			old_log_list = file.read().splitlines()
	
	# Check for new logs
	log_list = [log for log in current_logs if log not in old_log_list]

	if not log_list:
		print('No new logs found.')
		return log_data_list

	print('Found ', str(len(log_list)), ' new logs: ', str(log_list))

	# Process new logs (read content) and update tracking
	with open(tracking_file, 'a') as file:
		for log_file in log_list:
			file_path = os.path.join('LOGS', log_file)
			try:
				# Read as BYTES for encryption
				with open(file_path, 'rb') as log:
					content = log.read()
					# Store filename and content
					log_data_list.append((log_file, content))
				
				# Mark as processed
				file.write(log_file + '\n')
			except Exception as error:
				print('Error reading ', log_file, ': ', str(error))
	
	return log_data_list


#---------------------------------------------------------
# Encrypt, sign logs
#---------------------------------------------------------
def encrypt_logs(log_data_list):
	if not log_data_list:
		return None

	# Load the client's private key to sign the file
	with open('client_private_key.pem', 'rb') as key_file:
		client_private_key = RSA.import_key(key_file.read())
	
	# Load the server's public key to encrypt the AES key
	with open('server_public_key.pem', 'rb') as key_file:
		server_public_key = RSA.import_key(key_file.read())

	# Combine all log data into one byte stream
	# Format: [Filename Length (4 bytes)][Filename][Content Length (4 bytes)][Content]
	
	file_data = bytearray()
	for filename, content in log_data_list:
		header = f'\nSTART OF {filename}\n'.encode('utf-8')
		file_data.extend(header)
		file_data.extend(content)
	file_data = bytes(file_data)

	# Sign the file
	sig = file_signature(client_private_key, file_data)
	print('File signed successfully.')

	# Generate a random AES key for symmetric encryption
	aes_key = get_random_bytes(32)  # AES-256
	print('AES key generated.')
	
	# Encrypt the file with AES-256-GCM
	encrypted_file_data, tag, nonce = aes_file_encryption(aes_key, file_data)
	print('File encrypted with AES.')

	# Encrypt the AES key with RSA (server's public key)
	encrypted_aes_key = aes_key_encryption(server_public_key, aes_key)
	print('AES key encrypted with RSA.')

	return encrypted_aes_key, encrypted_file_data, tag, nonce, sig


#---------------------------------------------------------
# Start the client connection
#---------------------------------------------------------
def open_socket(encrypted_aes_key, encrypted_file_data, tag, nonce, sig):
	#input_serverip = input('Enter the server IP address: ')
	#input_serverport = input('Enter the server port: ')
	#server_ip = input_serverip
	#server_port = int(input_serverport)
	
	server_ip = '127.0.0.1'
	server_port = 12345
	
	print('Connecting to ', server_ip, ':', server_port, '...')

	# Create a socket and connect to the server
	csocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		csocket.connect((server_ip, server_port))
		print('Connection established at', datetime.now())

		# Send encrypted AES key
		csocket.sendall(encrypted_aes_key)
		print('Encrypted AES key sent.')
		
		# Send length of the encrypted file data
		csocket.sendall(len(encrypted_file_data).to_bytes(4, byteorder='big'))
		
		# Send encrypted file data
		csocket.sendall(encrypted_file_data)
		print('Encrypted file sent at', datetime.now())

		# Send the tag, nonce, and digital signature for verification
		csocket.sendall(tag)
		csocket.sendall(nonce) # Nonce is 16 bytes for AES-GCM
		csocket.sendall(sig)

		print('Signature sent at', datetime.now())
		
	except ConnectionRefusedError:
		print('Connection failed: Server is not running.')
	except Exception as error:
		print('An error occurred: ', error)
	except KeyboardInterrupt:
		print('\nAuto send stopped by user.')
		csocket.close()
	return


def process_log_cycle():
	# Generate Logs
	print('\nGenerating Logs')
	gather = generate_logs()

	# Gather Logs
	print('\nGathering Logs')
	log_data_list = log_gather(gather)

	if not log_data_list:
		print('No new logs found to send.')
		return

	# Encrypt Logs
	print('\nEncrypting Logs')
	encryption_result = encrypt_logs(log_data_list)
	
	if encryption_result:
		encrypted_aes_key, encrypted_file_data, tag, nonce, sig = encryption_result
		
		# Send Logs
		print('\nSending Logs')
		open_socket(encrypted_aes_key, encrypted_file_data, tag, nonce, sig)
	else:
		print('\nEncryption failed.')


def main():
	
	print('\n## Program started at', datetime.now(), ' ##')
	
	string_menu = '\n1.\tManual Log Send.\n2.\tAuto Log Send.\n\nSelect an option from above: '
	menu_select = input(string_menu)

	if menu_select == '1':
		process_log_cycle()

	elif menu_select == '2':
		print('Auto Log Send started. Press Any Key to stop.')
		try:
			while True:
				process_log_cycle()
				print('\nWaiting 2 seconds...')
				time.sleep(2)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
		except Exception as error:
			print('An error occurred: ', error)

	else:
		print('Invalid selection!')


if __name__ == '__main__':
	main()