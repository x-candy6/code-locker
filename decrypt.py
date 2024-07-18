from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

# Load the encrypted data
file_path = input("Enter the file to be decrypted:")
with open(file_path, 'rb') as f:
    data = f.read()

# Extract the salt, IV, and ciphertext
salt = data[:16]
iv = data[16:32]
ciphertext = data[32:]

# Derive the key from the password
pw= input("Enter the password: ")
password = pw.encode('utf-8') 

kdf = Scrypt(
    salt=salt,
    length=32,
    n=2**14,
    r=8,
    p=1,
    backend=default_backend()
)
key = kdf.derive(password)

# Decrypt the code
cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Execute the decrypted code
exec(plaintext.decode('utf-8'))
