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
		#self.server_ip = input('Enter the server IP address: ')
		#self.server_port = int(input('Enter the server port: '))
		self.server_ip = '192.168.200.4'
		self.server_port = 1234

	def key_generation(self):
		if not os.path.exists('client_private_key.pem'):
			print('Generating Keys...')
			key = RSA.generate(2048)
			open('client_private_key.pem', 'wb').write(key.export_key())
			open('client_public_key.pem', 'wb').write(key.publickey().export_key())
		
		print('Keys generated.')
	
	def receive_exact(self, sock, length):
		data = b''
		while len(data) < length:
			chunk = sock.recv(length - len(data))
			if not chunk:
				raise ConnectionError('Connection closed')
			data += chunk
		return data

	def	load_keys(self):
		self.key_generation()
		self.client_private_key = RSA.import_key(open('client_private_key.pem', 'rb').read())
		print('Loaded client private key.')
	
	def read_logs(self): # Read Logs
		with open('/var/log/syslog', 'rb') as f:
			return f.read()
    	
	# Digital Signature (SHA-512, RSA)
	def sign_logfile(self, file_data):
		hashed_object = SHA512.new(file_data)
		signpkcs = PKCS1_v1_5.new(self.client_private_key)
		sig = signpkcs.sign(hashed_object)
		return sig

	# Encrypt, sign logs
	def encrypt_logs(self, log_file):
		# Generate a random AES key for symmetric encryption
		aes_key = get_random_bytes(32)  # AES-256
		print('AES key generated.')

		aes_cipher = AES.new(aes_key, AES.MODE_GCM)  # GCM uses a nonce

		ciphertext, tag = aes_cipher.encrypt_and_digest(log_file)

		return ciphertext, tag, aes_cipher.nonce, aes_key

	# Encrypt the AES key with RSA (SHA-512)
	def aes_key_encryption(self, aes_key):
		rsa_cipher = PKCS1_OAEP.new(self.server_public_key)
		key_encrypted = rsa_cipher.encrypt(aes_key)
		return key_encrypted

	def send_data(self, encrypted_data):
		aes_key, encrypted_file_data, tag, nonce, sig = encrypted_data
		
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((self.server_ip, self.server_port))
		

	def send_data(self, encrypted_data):
		aes_key, encrypted_file_data, tag, nonce, sig = encrypted_data

		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((self.server_ip, self.server_port))

		try:
			# Receive server public key
			server_key_length = struct.unpack('>I', client_socket.recv(4))[0]
			server_key_bytes = self.receive_exact(client_socket, server_key_length)
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

			# Send RSA-encrypted AES key as normal
			header = len(encrypted_aes_key).to_bytes(4, 'big')
			client_socket.sendall(header)
			client_socket.sendall(encrypted_aes_key)

			# Send encrypted file IN CHUNKS
			file_size = len(encrypted_file_data)
			client_socket.sendall(file_size.to_bytes(4, 'big'))

			CHUNK_SIZE = 4096
			offset = 0
			while offset < file_size:
				end = offset + CHUNK_SIZE
				client_socket.sendall(encrypted_file_data[offset:end])
				offset = end

			# Send tag, nonce, signature normally
			for piece in [tag, nonce, sig]:
				header = len(piece).to_bytes(4, 'big')
				client_socket.sendall(header)
				client_socket.sendall(piece)


			client_socket.close()

			end_time = time.time()
			duration = end_time - start_time
			throughput_mbps = (bytes_sent * 8) / duration / 1_000_000

			print('Logs sent successfully.')
			print(f'Throughput: {throughput_mbps:.2f} Mbps')

		except ConnectionRefusedError:
			print('Connection failed: Server is not running.')
		except Exception as error:
			print('An error occurred: ', error)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
			self.client_socket.close()


	def send_logs(self):
		'''Start the client connection'''
		print('Connecting to ', self.server_ip, ':', self.server_port, '...')
		try:
			self.load_keys()
			logs = self.read_logs()
			print(f'Read {len(logs)} bytes from log file.')

			signature = self.sign_logfile(logs)
			print('Log file signed.')

			encrypted_file_data, tag, nonce, aes_key = self.encrypt_logs(logs)
			print('Log file encrypted.')

			encrypted_data = (aes_key, encrypted_file_data, tag, nonce, signature)
			print('AES key encrypted with RSA')
			self.send_data(encrypted_data)
		
		except Exception as e:
			print('Error during sending:', e)

	def send_manually(self):
		print(' Manual log send started.')
		self.send_logs()

	def auto_send(self):
		print('Auto_send started. Logs will be sent at 17:00 every day.')
		while True:
			now = datetime.now()
			if now.hour == 17 and now.minute == 0:
				print('\n', now.strftime('%H:%M:%S'), ' Scheduled send triggered!')
				self.send_logs()
				time.sleep(60)
			else:
				time.sleep(1)

def main():
	client = Client()
	print('\n## Program started at', datetime.now(), ' ##')
	
	string_menu = '\n1.\tManual Log Send.\n2.\tAuto Log Send at 17:00.\n\nSelect an option from above: '
	
	while True:
		menu_select = input(string_menu)

		if menu_select == '1':
			client.send_manually()

		elif menu_select == '2':
			auto_thread = threading.Thread(target=client.auto_send, daemon=True)
			auto_thread.start()
			print('Automatically sending logs at 17:00 daily.')

		elif menu_select == '3':
			print('Exiting program.')
			break

		else:
			print('Invalid selection!')

if __name__ == '__main__':
	main()