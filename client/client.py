import socket, os, logging, time
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from datetime import datetime


class Client:
    	
	def __init__(self):
		
		#self.server_ip = input('Enter the server IP address: ')
		#self.server_port = int(input('Enter the server port: '))
		
		self.server_ip = '127.0.0.1'
		self.server_port = 12345
		
	def read_logs(self):
		file = 'syslog'
		directory = '/var/log'
		file_path = os.path.join(directory, file)
		syslog_list = []
		with open(file_path, 'rb') as f:
			for line in f:
				syslog_list.append(line)
		
		return syslog_list, file_path

	# Digital Signature (SHA-512, RSA)
	def file_signature(self, private_key, file_data):
		hashed_object = SHA512.new(file_data)
		signpkcs = PKCS1_v1_5.new(private_key)
		sig = signpkcs.sign(hashed_object)
		return sig


	# Encrypt the AES key with RSA (SHA-512)
	def aes_key_encryption(self, public_key, aes_key):
		rsa_cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA512)
		key_encrypted = rsa_cipher.encrypt(aes_key)
		return key_encrypted


	# Encrypt the file with AES-256-GCM
	def aes_file_encryption(self, aes_key, file_data):
		aes_cipher = AES.new(aes_key, AES.MODE_GCM)  # GCM uses a nonce
		ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
		return ciphertext, tag, aes_cipher.nonce


	# Log Directory scan and collection
	def log_gather(self, read_logs):
		log_data_list = []

		log_list, file_path = read_logs()
		for l in log_list:
			print(l)
		tracking_file = 'processed_logs.txt'

		if not log_list:
			#print("not log list")
			log_list = self.read_logs()

		print('Found ', str(len(log_list)), ' new logs: ', str(log_list))

		# Process new logs (read content) and update tracking
		with open(tracking_file, 'a') as file:
			for log_file in log_list:
				try:
					current_time = datetime.now()#G#
					# Read as BYTES for encryption
					with open(file_path, 'rb') as log:
						content = log.read()
						# Store filename and content
						log_data_list.append((log_file, content))
					
					# Mark as processed
					file.write(log_file + '\n' + current_time)#G#
				except Exception as error:
					print('Error reading ', log_file, ': ', str(error))
		
		return log_data_list


	# Encrypt, sign logs
	def encrypt_logs(self, log_data_list):
		if not log_data_list:
			return None

		# Load the client's private key to sign the file
		with open('client_private_key.pem', 'rb') as key_file:
			client_private_key = RSA.import_key(key_file.read())
		
		# Load the server's public key to encrypt the AES key
		with open('server_public_key.pem', 'rb') as key_file:
			server_public_key = RSA.import_key(key_file.read())
		# Combine all log data into one byte stream
		
		file_data = bytearray()
		for filename, content in log_data_list:
			header = ('\nSTART OF ', filename, '\n').encode('utf-8')
			file_data.extend(header)
			file_data.extend(content)
			file_data.extend(b'\nEND OF ' + filename.encode('utf-8') + b'\n')
		file_data = bytes(file_data)

		# Sign the file
		sig = self.file_signature(client_private_key, file_data)
		print('File signed successfully.')

		# Generate a random AES key for symmetric encryption
		aes_key = get_random_bytes(32)  # AES-256
		print('AES key generated.')
		
		# Encrypt the file with AES-256-GCM
		encrypted_file_data, tag, nonce = self.aes_file_encryption(aes_key, file_data)
		print('File encrypted with AES.')

		# Encrypt the AES key with RSA (server's public key)
		encrypted_aes_key = self.aes_key_encryption(server_public_key, aes_key)
		print('AES key encrypted with RSA.')

		return encrypted_aes_key, encrypted_file_data, tag, nonce, sig


	# Start the client connection
	def open_socket(self, encrypted_aes_key, encrypted_file_data, tag, nonce, sig):
				
		print('Connecting to ', self.server_ip, ':', self.server_port, '...')

		# Create a socket and connect to the server
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			client_socket.connect((self.server_ip, self.server_port))
			print('Connection established at', datetime.now())

			# Send encrypted AES key
			client_socket.sendall(encrypted_aes_key)
			print('Encrypted AES key sent.')
			
			# Send length of the encrypted file data
			client_socket.sendall(len(encrypted_file_data).to_bytes(4, byteorder='big'))
			
			# Send encrypted file data
			client_socket.sendall(encrypted_file_data)
			print('Encrypted file sent at', datetime.now())

			# Send the tag, nonce, and digital signature for verification
			client_socket.sendall(tag)
			client_socket.sendall(nonce) # Nonce is 16 bytes for AES-GCM
			client_socket.sendall(sig)

			print('Signature sent at', datetime.now())
			
		except ConnectionRefusedError:
			print('Connection failed: Server is not running.')
		except Exception as error:
			print('An error occurred: ', error)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
			client_socket.close()
		return


	def process_log_cycle(self, read_logs):
		
		self.__init__()
		
		# Gather Logs
		print('\nGathering Logs')
		log_data_list = self.log_gather(read_logs)
		#if not log_data_list:
		#	print('No new logs found to send.')
		#	return

		# Encrypt Logs
		print('\nEncrypting Logs')
		encryption_result = self.encrypt_logs(log_data_list)
		
		if encryption_result:
			encrypted_aes_key, encrypted_file_data, tag, nonce, sig = encryption_result
			
			# Send Logs
			print('\nSending Logs')
			try:
				if ((encrypted_aes_key == None) or (encrypted_file_data == None) or (tag == None) or (nonce == None) or (sig == None)):
					print("one of these is empty!")
				else:
					self.open_socket(encrypted_aes_key, encrypted_file_data, tag, nonce, sig)
			
			except Exception as e: 
				print("something's wrong!")
			
		else:
			print('\nEncryption failed.')


	def auto_send(self):
		print(' Auto_send started. Logs will be sent at 17:00 every day.')
		while True:
			now = datetime.now()
			if now.hour == 17 and now.minute == 0:
				print('\n', now.strftime('%H:%M:%S'), ' Scheduled send triggered!')
				self.send_logs()
				time.sleep(60)
			if KeyboardInterrupt:
				print('\nAuto send stopped by user.')
				break


def main():
	client = Client()
	print('\n## Program started at', datetime.now(), ' ##')
	
	string_menu = '\n1.\tManual Log Send.\n2.\tAuto Log Send.\n\nSelect an option from above: '
	menu_select = input(string_menu)

	if menu_select == '1':
		client.process_log_cycle(client.read_logs)

	elif menu_select == '2':
		print('Automatic log sending (17:00 daily). Press Any Key to stop.')
		client.auto_send()

	elif menu_select == '3':
		print('Exiting program.')

	else:
		print('Invalid selection!')


if __name__ == '__main__':
	main()