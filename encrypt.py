from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

file_path = input("Enter the path to the Python script to be encrypted: ")

with open(file_path, 'rb') as file:
    plaintext = file.read()

password = input("Enter the password for encryption: ").encode()

# Generate a random salt
salt = os.urandom(16)

# Derive a key from the password
kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=default_backend()
)
key = kdf.derive(password)

# Generate a random IV
iv = os.urandom(16)

# Encryption
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Save output
output_file = file_path + '.enc'
with open(output_file, 'wb') as f:
    f.write(salt + iv + ciphertext)

print(f"The file has been encrypted and saved as {output_file}")
