import os
from crypto.hazmat.primitives.ciphers import Cipher, algorithms, modes
from crypto.hazmat.backends import default_backend
from crypto.hazmat.primitives import padding
def encrypt(plaintext, key):
    iv = os.urandom(32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)+padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext

def decrypt(ciphertext, key):

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update (ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted_padded) + unpadder.finalize() 
    
    return plaintext
key = os.urandom(32)
plaintext = (b"Hello Everyone! This is a secret message.")
iv, ciphertext = encrypt(plaintext, key)
print("Ciphertext:", ciphertext)
decrypted_plaintext = decrypt(ciphertext, key)
print("Decrypted Plaintext:", decrypted_plaintext)
