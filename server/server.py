import socket, os, struct
from pathlib import Path
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from datetime import datetime


class Server:

	def __init__(self, ip="192.168.200.4", port=1234):
		#self.ip = input('Enter the order IP address: ')
		#self.port = int(input('Enter the order port: '))
		self.ip = ip
		self.port = port

	def key_generation(self):
		if not os.path.exists('server_private_key.pem'):
			print("Generating Keys...")
			key = RSA.generate(2048)
			open('server_private_key.pem', 'wb').write(key.export_key())
			open('server_public_key.pem', 'wb').write(key.publickey().export_key())
		
		print("Keys generated.")
	
	def receive_exact(self, sock, length):
		data = b""
		while len(data) < length:
			chunk = sock.recv(length - len(data))
			if not chunk:
				raise ConnectionError('Connection closed')
			data += chunk
		return data

	def	load_keys(self):
		self.server_private_key = RSA.import_key(open('server_private_key.pem', 'rb').read())
		print("Loaded server private key.")
	
	def received(self, sock):
		length = struct.unpack('>I', self.receive_exact(sock, 4))[0]
		return self.receive_exact(sock, length)
	
	def decrypt_aes(self, encrypted_key):
		return PKCS1_OAEP.new(self.server_private_key).decrypt(encrypted_key)
	
	def decrypt_file(self, aes_key, encrypted_file, tag, nonce):
		cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
		return cipher.decrypt_and_verify(encrypted_file, tag)
	
	def verify(self, signature, data):
		hash = SHA512.new(data)
		return PKCS1_v1_5.new(self.client_public_key).verify(hash, signature)
	
	def main_belt(self, address, connection):
		print('Connection from', (address))
		print('Connection established at', datetime.now())
		
		try:
			server_pub = open("server_public_key.pem", "rb").read()
			connection.sendall(len(server_pub).to_bytes(4, "big") + server_pub)
			
			client_public_len = struct.unpack('>I', self.receive_exact(connection, 4))[0]
			receive_cpk = self.receive_exact(connection, client_public_len)
			self.client_public_key = RSA.import_key(receive_cpk)
			print('Client public key received')

			encrypted_key = self.received(connection)  # RSA-encrypted AES key
			encrypted_file = self.received(connection)
			tag = self.received(connection)
			nonce = self.received(connection)
			signature = self.received(connection)
			aes_key = self.decrypt_aes(encrypted_key)
			decrypted_file = self.decrypt_file(aes_key, encrypted_file, tag, nonce)

			print("Decrypted file:\n", decrypted_file.decode())

			if self.verify(decrypted_file, signature):
				print('Signature is valid.')
			else:
				print('Signature is invalid.')

			with open('received_file.txt', 'wb') as f:
				f.write(decrypted_file)

			connection.sendall(len(b'File received and processed successfully.').to_bytes(4, "big") + b'File received and processed successfully.')

			return decrypted_file
		
		except Exception as e:
			print("Error:", e)
		finally:
			connection.close()
			print('Connection closed at', datetime.now())

	def start(self):
		self.key_generation()
		self.load_keys()
		print('Connection opened at', datetime.now())
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((self.ip, self.port))  # Bind to any interface
		s.listen(1)
		print('Server is listening on', self.ip, ':', self.port)
		while True:
			connection, address = s.accept()
			self.main_belt(address, connection)
			#self.order(address, connection)
		
if __name__ == '__main__':
	Server().start()