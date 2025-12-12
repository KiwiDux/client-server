# Client

import socket, os, threading, time, struct
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from datetime import datetime


class Client:
	def __init__(self):
		# self.server_ip = input('Enter the server IP address: ')
		# self.server_port = int(input('Enter the server port: '))
		self.server_ip = '192.168.200.4'
		self.server_port = 1234

	# Generate AES keys
	def key_generation(self):
		if not os.path.exists('client_private_key.pem'): # path to the client's private key
			print('Generating Keys...') 
			key = RSA.generate(2048) # generate key with AES
			open('client_private_key.pem', 'wb').write(key.export_key())
			open('client_public_key.pem', 'wb').write(key.publickey().export_key())
		print('Keys generated.')
	
	# Receive and return the data received over the socket connection
	def socket_receive(self, sock, length):
		binary_data = b''
		while len(binary_data) < length:
			socket_chunk = sock.recv(length - len(binary_data))
			if not socket_chunk:
				raise ConnectionError('Connection closed')
			binary_data += socket_chunk
		return binary_data 

	def	loading_keys(self):
		self.key_generation() 
		self.client_private_key = RSA.import_key(open('client_private_key.pem', 'rb').read())
		print('Loaded client private key.')
	
	# Reading Ubuntu syslog files (as binary)
	def reading_logs(self): 
		with open('/var/log/syslog', 'rb') as f: 
			return f.read() 
    	
	# Digital Signature (SHA-512, RSA)
	def signing_log_files(self, file_data):
		hashed_object = SHA512.new(file_data)
		sign_pkcs = PKCS1_v1_5.new(self.client_private_key)
		sig = sign_pkcs.sign(hashed_object)
		return sig

	# Encrypt, sign logs
	def encrypting_logs(self, log_file):
		# Generate a random AES key for symmetric encryption
		aes_key = get_random_bytes(32)  # AES-256 key generation
		print('AES key generated.')
		aes_cipher = AES.new(aes_key, AES.MODE_GCM)  # GCM uses a nonce
		ciphertext, tag = aes_cipher.encrypt_and_digest(log_file)

		return ciphertext, tag, aes_cipher.nonce, aes_key

	# Encrypt the AES key with RSA (SHA-512)
	def aes_key_encryption(self, aes_key):
		rsa_cipher = PKCS1_OAEP.new(self.server_public_key)
		key_encrypted = rsa_cipher.encrypt(aes_key)
		return key_encrypted

	# Sending encrypted data over the socket
	def sending_data(self, encrypted_data):
		aes_key, encrypted_file_data, tag, nonce, sig = encrypted_data

		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((self.server_ip, self.server_port))

		try:
			# Receive server public key
			server_key_length = struct.unpack('>I', client_socket.recv(4))[0]
			server_key_bytes = self.socket_receive(client_socket, server_key_length)
			self.server_public_key = RSA.import_key(server_key_bytes)
			print('Received server public key')
			
			# Send client public key
			client_pub = open('client_public_key.pem', 'rb').read()
			client_socket.sendall(len(client_pub).to_bytes(4, 'big') + client_pub)
			print('Client public key sent.')

			encrypted_aes_key = self.aes_key_encryption(aes_key)

			start_time = time.time()
			bytes_sent = 0

			pieces = [encrypted_aes_key, encrypted_file_data, tag, nonce, sig]

			for piece in pieces:
				header = len(piece).to_bytes(4, 'big')
				client_socket.sendall(header)
				client_socket.sendall(piece)
				bytes_sent += len(header) + len(piece)

			client_socket.close()

			end_time = time.time()
			duration = end_time - start_time
			throughput_mbps = (bytes_sent * 8) / duration / 1_000_000

			print('Logs sent successfully.')
			print(f'\nThroughput: {throughput_mbps:.2f} Mbps')

		except ConnectionRefusedError:
			print('Connection failed: Server is not running.')
		except Exception as error:
			print('An error occurred: ', error)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
			self.client_socket.close()

	# Connect to client and send encypted logs
	def sending_logs(self):
		'''Start the client connection'''
		print('Connecting to ', self.server_ip, ':', self.server_port, '...')
		
		try:
			self.loading_keys()
			logs = self.reading_logs()
			print(f'Read {len(logs)} bytes from log file.')

			signature = self.signing_log_files(logs)
			print('Log file signed.')

			encrypted_file_data, tag, nonce, aes_key = self.encrypting_logs(logs)
			print('Log file encrypted.')

			encrypted_data = (aes_key, encrypted_file_data, tag, nonce, signature)
			print('AES key encrypted with RSA')
			self.sending_data(encrypted_data)
		
		except Exception as e:
			print('Error during sending: ', e)

	# Manual log sending
	def sending_manually(self):
		print('\nManual log sending started.')
		self.sending_logs()

	# Automatic log sending
	def auto_sending(self):
		print('\nAutomatic sending started. Logs will be sent at 17:00 every day.')
		
		while True:
			time_now = datetime.now()
			if time_now.hour == 17 and time_now.minute == 0:
				print('\n', time_now.strftime('%H:%M:%S'), ' Scheduled send triggered!')
				self.send_logs()
				time.sleep(60)
			else:
				time.sleep(1)

	def follow(self):
		# Tail the log file in binary mode and trigger sending when new data appears.
		log_path = '/var/log/syslog'
		print('\nLog monitoring started. Logs will be sent when updated.')

		while True:
			try:
				f = open(log_path, 'rb')
				# Seek to end to only observe new appended data
				f.seek(0, os.SEEK_END)

				while True:
					line = f.readline()
					if not line:
						# Check for rotation/truncation
						try:
							current_size = os.path.getsize(log_path)
						except FileNotFoundError:
							time.sleep(1)
							continue

						# If file has been truncated, reopen and seek to end
						if current_size < f.tell():
							try:
								f.close()
							except Exception:
								pass
							f = open(log_path, 'rb')
							f.seek(0, os.SEEK_END)
							continue

						time.sleep(0.1)
						continue

					# New bytes were read (bytes object)
					try:
						print('New log entry detected. Sending updated logs...')
					except Exception:
						pass
					# Trigger sending; existing sending_logs() reads the whole file as bytes
					self.sending_logs()

			except Exception as e:
				print('Error in follow():', e)
				try:
					f.close()
				except Exception:
					pass

	# Send a test file with a specified number of bytes
	def send_test_file(self):
		try:
			amount = int(input("Enter number of bytes to send: "))
			if amount <= 0:
				print("Invalid size.")
				return
			
			print(f"Generating {amount} bytes of test data...")
			test_data = os.urandom(amount)

			# Load keys
			self.loading_keys()

			# Sign
			signature = self.signing_log_files(test_data)
			print("Test data signed.")

			# Encrypt
			encrypted_file_data, tag, nonce, aes_key = self.encrypting_logs(test_data)
			print("Test data encrypted.")

			encrypted_data = (aes_key, encrypted_file_data, tag, nonce, signature)
			print("Sending test data now...")
			self.sending_data(encrypted_data)
		
		except ValueError:
			print("Please enter a valid number.")
		except Exception as e:
			print("Error sending test file:", e)

def main():
	client = Client()
	print('\n## Program started at', datetime.now(), ' ##')
	
	while True:
			print('\n--- Client Menu ---')
			print('1. Manual Log Send.')
			print('2. Auto Log Send at 17:00.')
			print('3. Send Logs when they update')
			print('4. Send test file (1, 100, 1000, or any number of bytes)')
			print('5. Exit')
			menu_selection = input('Select an option: ').strip()

			if menu_selection == '1':
				client.sending_manually()

			elif menu_selection == '2':
				auto_thread = threading.Thread(target=client.auto_sending, daemon=True)
				auto_thread.start()

			elif menu_selection == '3':
				# Start follow() in a background thread so it doesn't block the menu
				update_thread = threading.Thread(target=client.follow, daemon=True)
				update_thread.start()
			
			elif menu_selection == '4':
				client.send_test_file()
			
			elif menu_selection == '5':
				print('Exiting program.')
				break

			else:
				print('\n[-] Invalid option.')

if __name__ == '__main__':
	main()