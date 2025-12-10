import socket, os, logging, time, struct
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from datetime import datetime


class Client:
    	
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

	
	def __init__(self):
		
		#self.server_ip = input('Enter the server IP address: ')
		#self.server_port = int(input('Enter the server port: '))
		self.server_ip = '192.168.200.4'
		self.server_port = 1234
		
	
	def read_logs(self): # Read Logs
		with open('/var/log/syslog', 'rb') as f:
			return f.read()

	def key_generation(self):
		if not os.path.exists('client_private_key.pem'):
			key = RSA.generate(2048)
			open('client_private_key.pem', 'wb').write(key.export_key())
			open('client_public_key.pem', 'wb').write(key.publickey().export_key())
			print('Keys generated.')

	def	existing_cprivate(self):
		self.key_generation()
		with open('client_private_key.pem', 'rb') as key_file:
			self.client_private_key = RSA.import_key(key_file.read())

	def existing_spublic(self):
		with open('server_public_key.pem', 'rb') as key_file:
			self.server_public_key = RSA.import_key(key_file.read())

	def existing_cpublic(self):
		with open('client_public_key.pem', 'rb') as key_file:
			self.client_public_key = RSA.import_key(key_file.read())

	# Encrypt, sign logs
	def encrypt_logs(self, log_file):

		file_data = log_file
	
		self.existing_cprivate()
		self.existing_spublic()

		# Sign the file
		sig = self.file_signature(self.client_private_key, file_data)
		print('File signed successfully.')

		# Generate a random AES key for symmetric encryption
		aes_key = get_random_bytes(32)  # AES-256
		print('AES key generated.')
		
		# Encrypt the file with AES-256-GCM
		encrypted_file_data, tag, nonce = self.aes_file_encryption(aes_key, file_data)
		print('File encrypted with AES.')

		# Encrypt the AES key with RSA (server's public key)
		encrypted_aes_key = self.aes_key_encryption(self.server_public_key, aes_key)
		print('AES key encrypted with RSA.')

		return encrypted_aes_key, encrypted_file_data, tag, nonce, sig

	def open_socket(self):
		self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.client_socket.connect((self.server_ip, self.server_port))
			print('Connection established at', datetime.now())
			
			self.client_socket.sendall(self.client_public_key.export_key())
			print('Client public key sent.')
			
			server_key = struct.unpack(">I", self.client_socket.recv(4))[0]
			server_key_bytes = self.client_socket.recv(server_key)
			self.server_public_key = RSA.import_key(server_key_bytes)
			print("Received server public key")
		
		except ConnectionRefusedError:
			print('Connection failed: Server is not running.')
		except Exception as error:
			print('An error occurred: ', error)
		except KeyboardInterrupt:
			print('\nAuto send stopped by user.')
			self.client_socket.close()


	# Start the client connection
	def send_them(self, encrypted_aes_key, encrypted_file_data, tag, nonce, sig):
		
		print('Connecting to ', self.server_ip, ':', self.server_port, '...')
		
		self.existing_cpublic()
		try:
			
			# Send encrypted AES key
			self.client_socket.sendall(encrypted_aes_key)
			print('Encrypted AES key sent.')
			
			# Send length of the encrypted file data
			self.client_socket.sendall(len(self.client_public_key.export_key()).to_bytes(4, byteorder='big'))
			
			# Send encrypted file data
			self.client_socket.sendall(encrypted_file_data)
			print('Encrypted file sent at', datetime.now())

			# Send the tag, nonce, and digital signature for verification
			self.client_socket.sendall(tag)
			self.client_socket.sendall(nonce) # Nonce is 16 bytes for AES-GCM
			self.client_socket.sendall(sig)

			print('Signature sent at', datetime.now())	

		except Exception as e:
			print('Error during sending:', e)

		return


	def start_sequence(self):
		
		self.__init__()

		log_file = self.read_logs()
		
		self.open_socket()


		print('\nEncrypting Logs')
		encryption_result = self.encrypt_logs(log_file)
		
		if encryption_result:
			encrypted_aes_key, encrypted_file_data, tag, nonce, sig = encryption_result
			print('\nSending Logs')
			self.send_them(encrypted_aes_key, encrypted_file_data, tag, nonce, sig)




	def auto_send(self):
		print(' Auto_send started. Logs will be sent at 17:00 every day.')
		while True:
			now = datetime.now()
			if now.hour == 17 and now.minute == 0:
				print('\n', now.strftime('%H:%M:%S'), ' Scheduled send triggered!')
				self.start_sequence()
				time.sleep(60)
			if KeyboardInterrupt:
				print('\nAuto send stopped by user.')
				break


def main():
	client = Client()
	print('\n## Program started at', datetime.now(), ' ##')
	
	string_menu = '\n1.\tManual Log Send.\n2.\tAuto Log Send at 17:00.\n\nSelect an option from above: '
	menu_select = input(string_menu)

	if menu_select == '1':
		client.start_sequence()

	elif menu_select == '2':
		print('Automatic log sending (17:00 daily). Press Any Key to stop.')
		client.auto_send()

	elif menu_select == '3':
		print('Exiting program.')

	else:
		print('Invalid selection!')


if __name__ == '__main__':
	main()