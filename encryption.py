from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate a random key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt a plaintext message
def encrypt_message(plaintext, key):
    iv = os.urandom(16)  # Random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Padding the plaintext to be a multiple of the block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()  # Encode the IV and ciphertext together

# Decrypt a ciphertext message
def decrypt_message(encrypted_message, key):
    encrypted_data = base64.b64decode(encrypted_message.encode())
    iv = encrypted_data[:16]  # Extract the IV
    ciphertext = encrypted_data[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

if _name_ == "_main_":
    print("AES Encryption Tool")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    choice = input("Enter your choice (1/2): ")

    password = input("Enter a password for key generation: ")
    salt = b"this_is_a_salt"  # In practice, use a securely stored random salt
    key = generate_key(password, salt)

    if choice == "1":
        message = input("Enter the message to encrypt: ")
        encrypted = encrypt_message(message, key)
        print(f"Encrypted message: {encrypted}")
    elif choice == "2":
        encrypted_message = input("Enter the encrypted message: ")
        try:
            decrypted = decrypt_message(encrypted_message, key)
            print(f"Decrypted message: {decrypted}")
        except Exception as e:
            print(f"Decryption failed: {e}")
    else:
        print("Invalid choice. Please select 1 or 2.")