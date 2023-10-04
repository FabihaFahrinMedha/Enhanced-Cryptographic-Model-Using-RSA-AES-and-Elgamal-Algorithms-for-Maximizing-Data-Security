import psutil
# Get the memory usage before running the code
before_mem = psutil.Process().memory_info().rss / 1024 / 1024  # Convert from bytes to megabytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA
import mysql.connector
import time
print("\n+++DECRYPTION+++")
#start_time = time.time()

# Connect to the MySQL database
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="crypto_db"
)

# Create a cursor to execute SQL commands
mycursor = conn.cursor()
# Read the encrypted key from the database
mycursor.execute(
    "SELECT encrypted_aes_key FROM encrypted_data ORDER BY id DESC LIMIT 1")
encrypted_aes_key = mycursor.fetchone()[0]

# Read the encrypted message from the database
mycursor.execute(
    "SELECT ciphertext FROM encrypted_data ORDER BY id DESC LIMIT 1")
ciphertext = mycursor.fetchone()[0]


# Read the RSA private key from file (assuming it's in PEM format)
with open("private_key.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# Decrypt the AES key using RSA with OAEP padding
cipher_rsa = PKCS1_OAEP.new(private_key)
decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
print(">>Decrypting the Encrypted AES Key using RSA Private Key...")
print("[Decrypted AES Key]: ", decrypted_aes_key.hex())

# Decrypt the message using AES
iv = ciphertext[:AES.block_size]
ciphertext = ciphertext[AES.block_size:]
aes_cipher = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
decryptedtext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size)
print(">>Now decrypting the Ciphertext using Decrypted AES Key which is the actual AES key...")

# Print decrypted message
print("[Decrypted Message]: ", decryptedtext.decode())
print("\n")

# Close the connection
conn.close()
#end_time = time.time()
#elapsed_time = end_time - start_time
#print(f"Elapsed time: {elapsed_time:.4f} seconds")
# Get the memory usage after running the code
#after_mem = psutil.Process().memory_info().rss / 1024 / 1024  # Convert from bytes to megabytes

# Calculate the difference in memory usage
#mem_usage = after_mem - before_mem

# Print the memory usage
#print(f"Memory usage: {mem_usage:.2f} MB")