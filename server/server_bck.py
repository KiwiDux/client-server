import socket
import os
import time
from Cryptodome import Random
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from datetime import datetime



class Server:

	def __init__(self):
		
		#self.server_ip = input('Enter the server IP address: ')
		#self.server_port = int(input('Enter the server port: '))
		self.server_ip = '192.168.85.141'
		self.server_port = 1234

	def key_generation(self):
		if not os.path.exists('server_private_key.pem'):
			key = RSA.generate(2048)
			open('server_private_key.pem', 'wb').write(key.export_key())
			open('server_public_key.pem', 'wb').write(key.publickey().export_key())
			print('Keys generated.')


	def	existing_sprivate(self):
		self.key_generation()
		with open('server_private_key.pem', 'rb') as key_file:
			self.client_private_key = RSA.import_key(key_file.read())


	def existing_cpublic(self):
		with open('client_public_key.pem', 'rb') as key_file:
			self.client_public_key = RSA.import_key(key_file.read())

		# Load the client's public key
		self.client_key = os.path.join(os.path.dirname(__file__), 'client_public_key.pem')
	

	def existing_spublic(self):
		with open('server_public_key.pem', 'rb') as key_file:
			self.server_public_key = RSA.import_key(key_file.read())
	
	

	# Receive log file
	def receive_log_file(self, connection):


		server_key_path = os.path.join(os.path.dirname(__file__), 'server_private_key.pem')
		with open(server_key_path, 'rb') as key_file:
			private_key = RSA.import_key(key_file.read())


		# Receive the encrypted AES key
		aes_key_encrypted = connection.recv(256)  # RSA-encrypted AES key
		aes_key = self.aes_key_decryption(private_key, aes_key_encrypted)


		# Receive the length of the encrypted file data
		file_size = int.from_bytes(connection.recv(4), byteorder='big')


		# Receive the encrypted file data
		encrypted_file_data = b''
		while len(encrypted_file_data) < file_size:
			encrypted_file_data += connection.recv(file_size - len(encrypted_file_data))


		# Receive the AES tag, nonce, and signature
		tag = connection.recv(16)  # AES-GCM tag
		nonce = connection.recv(16)  # AES-GCM nonce (must be 16 bytes)
		signature = connection.recv(256)  # RSA signature


		# Decrypt the file using the decrypted AES key
		try:
			decrypted_file_data = self.aes_file_decryption(aes_key, encrypted_file_data, tag, nonce)
		except ValueError as e:
			print('Decryption failed:', e)
			return None


		# Save the decrypted file
		received_path = os.path.join(os.path.dirname(__file__), 'received_file.txt')
		with open(received_path, 'wb') as file:
			file.write(decrypted_file_data)


		
		self.existing_cpublic()


		# Verify the signature
		if self.sig_verification(self.client_public_key, decrypted_file_data, signature):
			print('Signature is valid.')
		else:
			print('Signature is invalid.')


		return decrypted_file_data


	
	# Store log report securely (as an encrypted file) 

	# AES-256 key must be 32 bytes long
	#aes_key = os.urandom(32) # Randomly generate a key (securely store this in practice)

	def encrypt_stored_file(self, decrypted_file_data):
		if not decrypted_file_data:
			return None


		# Normalize to bytes
		if not isinstance(decrypted_file_data, (bytes, bytearray)):
			file_data = str(decrypted_file_data).encode('utf-8')
		else:
			file_data = bytes(decrypted_file_data)


		# Load the servers's private key to sign the file
		self.existing_sprivate()


		# Load the server's public key to encrypt the AES key
		self.existing_cpublic()

		# Sign the file
		hashed_object = SHA512.new(file_data)
		signer = PKCS1_v1_5.new(self.server_private_key)
		signature = signer.sign(hashed_object)


		# AES key, encrypt file and AES key
		aes_key = get_random_bytes(32)
		encrypted_file_data, tag, nonce = self.aes_file_encryption(aes_key, file_data)
		encrypted_aes_key = self.aes_key_encryption(self.client_public_key, aes_key)


		return encrypted_aes_key, encrypted_file_data, tag, nonce, signature


	def verify_signature(self, decrypted_file_data, signature):
		# Verify the signature
		if self.sig_verification(self.client_public_key, decrypted_file_data, signature):
			print('Signature is valid.')
		else:
			print('Signature is invalid.')


	def start_server(self,):
		

		self.__init__()

		try:
			print('Connection closed at', datetime.now())
			server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			server_socket.bind((self.server_ip, self.server_port))  # Bind to any interface
			server_socket.listen(1)
			print('Server is listening on port', self.server_port)
			connection = server_socket.accept()
			address = server_socket.accept()
			print('Connection from', (address))
			print('Connection established at', datetime.now())

		except Exception as error:
			print('An error occurred: ', error)

		except KeyboardInterrupt:
			print('\nSocket closed by by server.')
			server_socket.close()
		
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
		signature = connection.recv(256)  # RSA signature
		print('Signature received.', (signature))


		# Load the server's private key (path resolved relative to this script file)
		server_key_path = os.path.join(os.path.dirname(__file__), 'server_private_key.pem')
		with open(server_key_path, 'rb') as key_file:
			private_key = RSA.import_key(key_file.read())


		# Decrypt the AES key
		aes_key = self.aes_key_decryption(private_key, aes_key_encrypted)
		print('AES key decrypted.', (aes_key))


		# Decrypt the file using the decrypted AES key
		try:
			decrypted_file_data = self.aes_file_decryption(aes_key, encrypted_file_data, tag, nonce)
			print('File decrypted successfully.', (decrypted_file_data))
		except ValueError as e:
			print('Decryption failed: ', e, e)
			connection.close()
			return


		# Save the decrypted file
		received_path = os.path.join(os.path.dirname(__file__), 'received_file.txt')
		with open(received_path, 'wb') as file:
			file.write(decrypted_file_data)
		print('File saved as ', received_path)


		# Load the client's public key
		self.existing_cpublic()


		## Encrypt logs
		print('\nEncrypting Logs')
		encryption_result = self.encrypt_stored_file(decrypted_file_data)
		if encryption_result:
			self.encrypted_aes_key, encrypted_file_data, tag, nonce, signature = encryption_result
		else:
			print('\nEncryption failed.')


		## Save logs
		self.save_recieved_file(encryption_result)



	def save_recieved_file(self, encryption_result, address):
		
		# Ensure folder exists
		save_folder = ('/Desktop/LOGFILES/', address)

		if not os.path.exists(save_folder):
			os.makedirs(save_folder, exist_ok=True)
			current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
			filename = os.path.join(save_folder, current_time + '.txt')
		
		if not encryption_result:
			return
		
		# Expect tuple: (encrypted_aes_key, encrypted_file_data, tag, nonce, signature)
		try:
			encrypted_aes_key, encrypted_file_data, tag, nonce, signature = encryption_result
		except Exception:
			with open(filename, 'w', encoding='utf-8') as f:
				f.write(str(encryption_result))
				return
				
		with open(filename, 'w', encoding='utf-8') as f:
			f.write('encrypted_aes_key: ' + (encrypted_aes_key).decode('ascii') + '\n')
			f.write('encrypted_file_data: ' + (encrypted_file_data).decode('ascii') + '\n')
			f.write('tag: ' + (tag).decode('ascii') + '\n')
			f.write('nonce: ' + (nonce).decode('ascii') + '\n')
			f.write('signature: ' + (signature).decode('ascii'))



	def receive_file(self):


		return



		

if __name__ == '__main__':
	Server.start_server()