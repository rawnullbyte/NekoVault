import os
from Crypto.Cipher import AES
from argon2 import low_level

def hashPassword(password: str, salt: bytes | None = None):
    salt = os.urandom(16) if salt is None else salt
    return low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    ), salt

def encrypt(plaintext: str, key: bytes):
    if not isinstance(plaintext, str): # Convert to string
        plaintext = json.dumps(plaintext) 

    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    # Nonce (16b) + Tag (16b) + Data
    return (cipher.nonce + tag + ciphertext).hex()

def decrypt(hex_data: str, key: bytes):
    raw = bytes.fromhex(hex_data)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()