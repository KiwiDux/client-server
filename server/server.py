# Server

import socket, os, struct, random, time, threading
from pathlib import Path
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Hash import SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from datetime import datetime


class Server:

	def __init__(self, ip='192.168.200.4', port=1234):
		#self.ip = input('Enter the order IP address: ')
		#self.port = int(input('Enter the order port: '))
		self.ip = ip
		self.port = port
		self.encrypted_folder = 'encrypted_logs'
		# Create folder if it doesn't exist
		if not os.path.exists(self.encrypted_folder):
			os.makedirs(self.encrypted_folder)

	def key_generation(self):
		if not os.path.exists('server_private_key.pem'):
			print('Generating Keys...')
			key = RSA.generate(2048)
			open('server_private_key.pem', 'wb').write(key.export_key())
			open('server_public_key.pem', 'wb').write(key.publickey().export_key())
		
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
		self.server_private_key = RSA.import_key(open('server_private_key.pem', 'rb').read())
		print('Loaded server private key.')
	
	def rsa_encrypt_for_storage(self, data):
		server_pub = RSA.import_key(open('server_public_key.pem', 'rb').read())
		cipher = PKCS1_OAEP.new(server_pub)
		return cipher.encrypt(data)

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
			server_pub = open('server_public_key.pem', 'rb').read()
			connection.sendall(len(server_pub).to_bytes(4, 'big') + server_pub)
			
			client_public_len = struct.unpack('>I', self.receive_exact(connection, 4))[0]
			receive_cpk = self.receive_exact(connection, client_public_len)
			self.client_public_key = RSA.import_key(receive_cpk)
			print('Client public key received')

			encrypted_key = self.received(connection) # RSA-encrypted AES key
			encrypted_file = self.received(connection)
			tag = self.received(connection)
			nonce = self.received(connection)
			signature = self.received(connection)
			aes_key = self.decrypt_aes(encrypted_key)
			decrypted_file = self.decrypt_file(aes_key, encrypted_file, tag, nonce)

			if self.verify(signature, decrypted_file):
				print('Signature is valid.')
			else:
				print('Signature is invalid.')
			
			# --- Secure Storage Encryption (Hybrid: AES + RSA) ---

			# 1. Use AES key
			storage_key = aes_key

			# 2. Encrypt file with AES-GCM
			storage_cipher = AES.new(storage_key, AES.MODE_GCM)
			storage_ciphertext, storage_tag = storage_cipher.encrypt_and_digest(decrypted_file)
			storage_nonce = storage_cipher.nonce

			# 3. Encrypt AES key with server public RSA key
			server_pub = RSA.import_key(open('server_public_key.pem', 'rb').read())
			rsa_cipher = PKCS1_OAEP.new(server_pub)
			encrypted_storage_key = rsa_cipher.encrypt(storage_key)

			# 4. Generate filename
			randnum = random.randint(1, 9999)
			base_filename = os.path.join(self.encrypted_folder, f'{address[0]}_{address[1]}_received_file_{randnum}')

			# 5. Save AES-encrypted file
			with open(base_filename + '.enc', 'wb') as f:
				f.write(storage_ciphertext)

			# Save RSA-encrypted AES key
			with open(base_filename + '.key.enc', 'wb') as f:
				f.write(encrypted_storage_key)

			# Save GCM metadata
			with open(base_filename + '.nonce', 'wb') as f:
				f.write(storage_nonce)

			with open(base_filename + '.tag', 'wb') as f:
				f.write(storage_tag)

			print('Encrypted file stored securely:')
			print(base_filename + '.enc')
			print('  AES key (RSA-encrypted):', base_filename + '.key.enc')
			print('  GCM tag:', base_filename + '.tag')
			print('  GCM nonce:', base_filename + '.nonce')


			connection.sendall(len(b'File received and processed successfully.').to_bytes(4, 'big') + b'File received and processed successfully.')

			return decrypted_file
		
		except Exception as e:
			print('Error:', e)
		finally:
			connection.close()
			print('Connection closed at', datetime.now())

	def decrypt_stored_file(self, base_filename):
		'''Decrypt a file that was stored using hybrid AES+RSA encryption.
		
		Expects:
		- encrypted_logs/base_filename.enc (AES-encrypted file)
		- encrypted_logs/base_filename.key.enc (RSA-encrypted AES key)
		- encrypted_logs/base_filename.tag (GCM authentication tag)
		- encrypted_logs/base_filename.nonce (GCM nonce)
		'''
		try:
			# Load encrypted AES key and decrypt it
			with open(os.path.join(self.encrypted_folder, base_filename + '.key.enc'), 'rb') as f:
				encrypted_aes_key = f.read()
			aes_key = PKCS1_OAEP.new(self.server_private_key).decrypt(encrypted_aes_key)
			print(f'[*] AES key decrypted from {base_filename}.key.enc')

			# Load nonce, tag, and ciphertext
			with open(os.path.join(self.encrypted_folder, base_filename + '.nonce'), 'rb') as f:
				nonce = f.read()
			with open(os.path.join(self.encrypted_folder, base_filename + '.tag'), 'rb') as f:
				tag = f.read()
			with open(os.path.join(self.encrypted_folder, base_filename + '.enc'), 'rb') as f:
				ciphertext = f.read()

			# Decrypt and verify
			cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
			plaintext = cipher.decrypt_and_verify(ciphertext, tag)
			print(f'[+] File decrypted and verified successfully.')
			
			# Save plaintext
			output_file = os.path.join(self.encrypted_folder, base_filename + '_decrypted.txt')
			with open(output_file, 'wb') as f:
				f.write(plaintext)
			print(f'[+] Decrypted content saved to {output_file}')
			print(f'\n--- Decrypted Content (first 500 chars) ---')
			print(plaintext[:500].decode('utf-8', errors='replace'))
			print('--- End of Preview ---\n')
			
		except FileNotFoundError as e:
			print(f'[-] Error: Missing file - {e}')
		except Exception as e:
			print(f'[-] Decryption failed: {e}')

	def list_encrypted_files(self):
		'''List all encrypted files in the encrypted_logs directory.'''
		enc_files = {}
		for file in os.listdir(self.encrypted_folder):
			if file.endswith('.enc') and not file.endswith('.key.enc'):
				# Extract base filename
				base = file.replace('.enc', '')
				if base not in enc_files:
					enc_files[base] = {'enc': None, 'key': None, 'tag': None, 'nonce': None}
				enc_files[base]['enc'] = file

		for file in os.listdir(self.encrypted_folder):
			if file.endswith('.key.enc'):
				base = file.replace('.key.enc', '')
				if base not in enc_files:
					enc_files[base] = {'enc': None, 'key': None, 'tag': None, 'nonce': None}
				enc_files[base]['key'] = file

			elif file.endswith('.tag'):
				base = file.replace('.tag', '')
				if base not in enc_files:
					enc_files[base] = {'enc': None, 'key': None, 'tag': None, 'nonce': None}
				enc_files[base]['tag'] = file

			elif file.endswith('.nonce'):
				base = file.replace('.nonce', '')
				if base not in enc_files:
					enc_files[base] = {'enc': None, 'key': None, 'tag': None, 'nonce': None}
				enc_files[base]['nonce'] = file

		if not enc_files:
			print('[-] No encrypted files found.')
			return None

		print(f'\n[+] Found {len(enc_files)} encrypted file set(s):\n')
		for i, (base, files) in enumerate(enc_files.items(), 1):
			complete = all([files['enc'], files['key'], files['tag'], files['nonce']])
			status = '[COMPLETE]' if complete else '[INCOMPLETE]'
			print(f'{i}. {base} {status}')
			if files['enc']:
				print(f'   - Data: {files['enc']}')
			if files['key']:
				print(f'   - Key: {files['key']}\n')

		return enc_files
	
	def start(self):
		print('Connection opened at', datetime.now())
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		s.bind((self.ip, self.port))  # Bind to any interface
		s.listen(1)
		print('Server is listening on', self.ip, ':', self.port)
		while True:
			connection, address = s.accept()
			start = time.time()
			data = self.main_belt(address, connection)
			size_bits = len(data) * 8
			end = time.time()
			throughput = (size_bits / (end - start)) / 1000000  # in Mbps
			#print(f'Receieved:\n{data.decode()}\n| Throughput: {throughput:.2f} Mbps')
			print(f'Throughput: {throughput:.2f} Mbps')


	def start_threaded(self):
		'''Start server in background thread and present interactive menu.'''
		self.key_generation()
		self.load_keys()

		# Start server in background thread
		server_thread = threading.Thread(target=self.start, daemon=True)
		server_thread.start()
		print('\n[+] Server started in background.')
		
		# Main menu loop
		while True:
			print('\n--- Server Menu ---')
			print('1. List encrypted files')
			print('2. Decrypt a file')
			print('3. Exit')
			choice = input('Select an option: ').strip()

			if choice == '1':
				self.list_encrypted_files()

			elif choice == '2':
				enc_files = self.list_encrypted_files()
				if enc_files:
					try:
						idx = int(input('\nEnter file number to decrypt: '))
						base_filename = list(enc_files.keys())[idx - 1]
						self.decrypt_stored_file(base_filename)
					except (ValueError, IndexError):
						print('[-] Invalid selection.')

			elif choice == '3':
				print('Exiting...')
				break

			else:
				print('[-] Invalid option.')
		
if __name__ == '__main__':
	Server().start_threaded()