import socket
import os
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from datetime import datetime


class Server:

	def __init__(self):
		
		#self.ip = input('Enter the server IP address: ')
		#self.port = int(input('Enter the server port: '))
		self.ip = '192.168.85.141'
		self.port = 1234


	def key_generation(self):
		if not os.path.exists('server_private_key.pem'):
			key = RSA.generate(2048)
			open('server_private_key.pem', 'wb').write(key.export_key())
			open('server_public_key.pem', 'wb').write(key.publickey().export_key())
			print('Keys generated.')


	def	existing_server_key(self):
		self.key_generation()
		self.server_private_key = RSA.import_key(open("server_private_key.pem", "rb").read())
		self.server_public_key = RSA.import_key(open("server_public_key.pem", "rb").read())


	def existing_cpublic(self):
		self.client_public_key = RSA.import_key(open("client_public_key.pem", "rb").read())

	
	def decrypt_aes(self):
		return PKCS1_OAEP.new(self.server_private_key).decrypt(self.aes_key)
		 

	def verify(self, signature, decrypted_file):
		hash = SHA512.new(decrypted_file)
		return PKCS1_v1_5.new(self.client_public_key).verify(hash, signature)
		

	def decrypt_file(self, aes_key, encrypted_file, tag, nonce):
		cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
		return cipher.decrypt_and_verify(encrypted_file, tag)
		

	def receive_log_file(self, connection):

		# Receive the length of the encrypted file data
		self.file_size = int.from_bytes(connection.recv(4), byteorder='big')

		encrypted_key = self.receive(connection)
		encrypted_file = self.receive(connection)
		tag = self.connection.recv(16)
		nonce = self.connection.recv(16)
		signature = self.connection.recv(256)
		aes_key = self.decrypt_aes(encrypted_key)
		decrypted_file = self.decrypt_file(aes_key, encrypted_file, tag, nonce)


		self.aes_file_decryption = (self.aes_key, encrypted_file, tag, nonce)

		if self.verify(decrypted_file, signature):
			print('Signature is valid.')

		else:
			print('Signature is invalid.')

		# Receive the encrypted file data
		self.encrypted_file = b''
		while len(encrypted_file) < self.file_size:
			encrypted_file += connection.recv(self.file_size - len(encrypted_file))

		# Save the decrypted file
		received_path = os.path.join(os.path.dirname(__file__), 'received_file.txt')
		with open(received_path, 'wb') as file:
			file.write(self.decrypted_file_data)



	def save_recieved_file(self, address):
		
		# Ensure folder exists
		save_folder = ('/Desktop/LOGFILES/', address)

		if not os.path.exists(save_folder):
			os.makedirs(save_folder, exist_ok=True)
			current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
			filename = os.path.join(save_folder, current_time + '.txt')

		import base64	

		with open(filename, 'w', encoding='utf-8') as f:
			f.write('encrypted_aes_key: ' + (self.encrypted_aes_key).decode(base64) + '\n')
			f.write('encrypted_file: ' + (self.encrypted_file).decode(base64) + '\n')
			f.write('tag: ' + (self.tag).decode(base64) + '\n')
			f.write('nonce: ' + (self.nonce).decode(base64) + '\n')
			f.write('signature: ' + (self.signature).decode(base64))

		with open("received_file.txt", "wb") as f:
			f.write(self.decrypted_file_data)



	def server(self, tag, nonce, signature):
		
		self.__init__()

		# Receive the encrypted AES key
		aes_key_encrypted = self.connection.recv(256)  # RSA-encrypted AES key
		print('Encrypted AES key received.', (aes_key_encrypted))

		# Load the server's private key (path resolved relative to this script file)
		server_key_path = self.server_private_key
		with open(server_key_path, 'rb') as key_file:
			self.server_private_key = RSA.import_key(key_file.read())
		

		# Decrypt the file using the decrypted AES key
		try:
			self.decrypted_file_data = self.aes_file_decryption(self.aes_key, self.encrypted_file, tag, nonce)
			print('File decrypted successfully.', (self.decrypted_file_data))
		except ValueError as e:
			print('Decryption failed: ', e, e)
			self.connection.close()
			return

		# Load the client's public key
		self.existing_cpublic()

	
	def start(self):
		self.existing_server_key()
		print('Connection closed at', datetime.now())
		server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server_socket.bind((self.ip, self.port))  # Bind to any interface
		server_socket.listen(1)
		print('Server is listening on ',self.ip, ':', self.port)
		while True:
			self.connection = server_socket.accept()
			self.address = server_socket.accept()
			print('Connection from', (self.address))
			print('Connection established at', datetime.now())
			self.server()
		



		

if __name__ == '__main__':
	Server.start()