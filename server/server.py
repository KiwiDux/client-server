import socket, os, struct
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from datetime import datetime


class Server:

	def __init__(self):
		
		#self.ip = input('Enter the order IP address: ')
		#self.port = int(input('Enter the order port: '))
		self.ip = '127.0.0.1'
		self.port = 1234
		return


	def key_generation(self):
		if not os.path.exists('server_private_key.pem'):
			key = RSA.generate(2048)
			open('server_private_key.pem', 'wb').write(key.export_key())
			open('server_public_key.pem', 'wb').write(key.publickey().export_key())
		
		print('Keys generated.')


	def	existing_server_key(self):
		self.key_generation()
		self.server_private_key = RSA.import_key(open('server_private_key.pem', 'rb').read())
	
	def decrypt_aes(self):
		return PKCS1_OAEP.new(self.server_private_key).decrypt(self.aes_key)
		 
	def received(self, sock):
		length = struct.unpack('>I', self.receive_exact(sock, 4))[0]
		return self.receive_exact(sock, length)

	def receive_exact(self, sock, length):
		data = b''
		while len(data) < length:
			packet = sock.recv(length - len(data))
			if not packet:
				raise ConnectionError('Connection closed')
			data += packet
		return data, sock
	
	def verify(self, signature, data):
		hash = SHA512.new(data)
		return PKCS1_v1_5.new(self.client_public_key).verify(hash, signature)
		

	def decrypt_file(self, aes_key, encrypted_file, tag, nonce):
		cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
		return cipher.decrypt_and_verify(encrypted_file, tag)
	
	def save_recieved_file(self, address):
		
		# Ensure folder exists
		save_folder = ('/Desktop/LOGFILES/', address)

		if not os.path.exists(save_folder):
			os.makedirs(save_folder, exist_ok=True)
			current_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
			filename = os.path.join(save_folder, current_time + '.txt')

		import base64	

		with open(filename, 'w', encoding='utf-8') as f:
			f.write('encrypted_aes_key: ' + (self.encrypted_key).decode(base64) + '\n')
			f.write('encrypted_file: ' + (self.encrypted_file).decode(base64) + '\n')
			f.write('tag: ' + (self.tag).decode(base64) + '\n')
			f.write('nonce: ' + (self.nonce).decode(base64) + '\n')
			f.write('signature: ' + (self.signature).decode(base64))

	def main_belt(self, address, connection):
		print('Connection from', (address))
		print('Connection established at', datetime.now())
		self.__init__()
		self.existing_server_key()
		
		try:
			
			server_pub = open("server_public_key.pem", "rb").read()
			connection.sendall(len(server_pub).to_bytes(4, "big") + server_pub)
			
			client_public_len = struct.unpack('>I', self.receive_exact(connection, 4))[0]
			receive_cpk = self.receive_exact(connection, client_public_len)
			self.client_public_key = RSA.import_key(receive_cpk)
			print('Client public key received')

			self.encrypted_key = self.received(connection)  # RSA-encrypted AES key
			self.encrypted_file = self.received(connection)
			self.tag = self.received(connection)
			self.nonce = self.received(connection)
			self.signature = self.received(connection)

			self.aes_key = self.decrypt_aes(self.encrypted_key)
			self.decrypted_file = self.decrypt_file(self.aes_key, self.encrypted_file, self.tag, self.nonce)

			aes_file_decryption = (self.aes_key, self.encrypted_file, self.tag, self.nonce)

			if self.verify(self.decrypted_file, self.signature):
				print('Signature is valid.')

			else:
				print('Signature is invalid.')


			with open('received_file.txt', 'wb') as f:
				f.write(self.decrypted_file)
		
		except Exception as e:
			print('Error:', e)
		
		self.save_recieved_file(address)

		return


	#def order(self, address, connection):
	#	self.__init__()
	#	self.existing_server_key()
	#	self.client_public()
	#	self.main_belt(address, connection)
		
	def start(self):
		print('Connection opened at', datetime.now())
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.bind((self.ip, self.port))  # Bind to any interface
		s.listen(1)
		print('Server is listening on', self.ip, ':', self.port)
		while True:
			connection, address = s.accept()
			self.main_belt(address, connection)
			#self.order(address, connection)

	
		
if __name__ == '__main__':
	Server().start()