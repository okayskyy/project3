from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def encrypt_private_key(key: bytes) -> str:
    # Get encryption key from the environment variable
    encryption_key = os.getenv('NOT_MY_KEY').encode('utf-8')
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    
    pad_length = 16 - len(key) % 16
    padded_key = key + bytes([pad_length]) * pad_length

    # Encrypt the key
    encrypted_key = encryptor.update(padded_key) + encryptor.finalize()

    
    encrypted_data = base64.b64encode(iv + encrypted_key).decode('utf-8')
    
    return encrypted_data

def decrypt_private_key(encrypted_data: str) -> bytes:
    
    encryption_key = os.getenv('NOT_MY_KEY').encode('utf-8')
    
    # Decode the base64 encrypted data
    encrypted_data = base64.b64decode(encrypted_data)
    
    # Extract the IV and encrypted key
    iv = encrypted_data[:16]
    encrypted_key = encrypted_data[16:]
    
    # Initialize AES cipher for decryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the key
    decrypted_key = decryptor.update(encrypted_key) + decryptor.finalize()

    
    pad_length = decrypted_key[-1]
    return decrypted_key[:-pad_length]
