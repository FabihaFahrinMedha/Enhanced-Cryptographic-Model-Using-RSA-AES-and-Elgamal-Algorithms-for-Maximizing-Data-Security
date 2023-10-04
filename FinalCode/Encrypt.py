import psutil
# Get the memory usage before running the code
before_mem = psutil.Process().memory_info().rss / 1024 / 1024  # Convert from bytes to megabytes

from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import mysql.connector
import time
start_time = time.time()

# establish a connection to MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password=""
)

# Create the crypto_db database if it doesn't already exist
mycursor = conn.cursor()
mycursor.execute("CREATE DATABASE IF NOT EXISTS crypto_db")

# Use the crypto_db database
mycursor.execute("USE crypto_db")

# create the "encrypted_data" table
mycursor = conn.cursor()
mycursor.execute("""
    CREATE TABLE IF NOT EXISTS encrypted_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        encrypted_aes_key VARBINARY(1024) NOT NULL,
        ciphertext VARBINARY(1024) NOT NULL
    )
""")


print("\n+++ENCRYPTION+++")

# Read the aes_key from the file
with open("aes_key.txt", "r") as f:
    aes_key_hex = f.read()

# Decode the hex string into bytes
aes_key = bytes.fromhex(aes_key_hex)

# Encryption using AES
plaintext = input("""[Enter your message]: """).encode()
# print("[Plaintext]: ", plaintext)

padded_plaintext = pad(plaintext, AES.block_size)
ciphertext = b""
iv = Random.new().read(AES.block_size)
aes = AES.new(aes_key, AES.MODE_CBC, iv)
ciphertext = iv + aes.encrypt(padded_plaintext)
print(">>Fetching the AES Key...")
print("[Encryption Key]: ", aes_key.hex())

# Print encrypted message
print(">>Encrypting the message using AES Key...")
print("[Ciphertext]: ", ciphertext.hex())
# generate a new RSA key pair (use a longer key size for real-world use)
key = RSA.generate(2048)

# save the private key to a file
with open("private_key.pem", "wb") as f:
    f.write(key.export_key())

# encrypt the AES key using RSA with OAEP padding
cipher_rsa = PKCS1_OAEP.new(key)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)
print(">>Encrypting AES Key using RSA Public Key...")
print("[Encrypted AES Key]: ", encrypted_aes_key.hex())
print("\n")

# insert the encrypted key and ciphertext values into the database
mycursor.execute("""
    INSERT INTO encrypted_data (encrypted_aes_key, ciphertext)
    VALUES (%s, %s)
""", (encrypted_aes_key, ciphertext))
conn.commit()
#end_time = time.time()
#elapsed_time = end_time - start_time
#print(f"Elapsed time: {elapsed_time:.4f} seconds")

# Get the memory usage after running the code
#after_mem = psutil.Process().memory_info().rss / 1024 / 1024  # Convert from bytes to megabytes

# Calculate the difference in memory usage
#mem_usage = after_mem - before_mem

# Print the memory usage
#print(f"Memory usage: {mem_usage:.2f} MB")