import string
import secrets
import hashlib
def generate_and_hash_keys():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(256))
    hash1 = hashlib.sha256(password.encode(), usedforsecurity=True)
    return password, hash1.hexdigest()
    
# Test (ignore or delete)
password, hashed_password = generate_and_hash_keys()
print("Generated Password:", password)
print("Hashed Password:", hashed_password)