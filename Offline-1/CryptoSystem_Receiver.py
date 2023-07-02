# Import socket module
import socket, pickle    
from Diffie_Hellman import *
from AES import *
from RSA import *

key_length = 256     
 
print("This is Bob")
# Create a socket object
s = socket.socket()        
 
# Define the port on which you want to connect
port = 1337               
 
# connect to the server on local computer
s.connect(('127.0.0.1', port))

# Initialize Bob RSA
rsa = RSA(key_length)

bob_public_key, bob_n = rsa.generate_public_key()
bob_private_key = rsa.generate_private_key(bob_public_key)

# Send Alice my(Bob) public key
if "rsa public key" in s.recv(1024).decode():
    s.send(str(bob_public_key).encode())
if "rsa n" in s.recv(1024).decode():
    s.send(str(bob_n).encode())
    
# Receive data from the Alice(server) and decoding to get the string.
s.send("Send me prime number".encode())
prime = int(s.recv(1024).decode())
prime = decrypt(prime, bob_private_key, bob_n)

s.send("Send me generator".encode())
gen = int(s.recv(1024).decode())
gen = decrypt(gen, bob_private_key, bob_n)

# Sharing public key of BOB
b = gen_prime((key_length//2)+2)
print("Private Key: " + str(b))
B = fast_mod_exp(gen, b, prime)
print("Public Key: " + str(B))

# Request for ALice's DH public key
s.send("Send me DH public key".encode())
# Receive sender public key
A = int(s.recv(1024).decode())
A = decrypt(A, bob_private_key, bob_n)

# Signal Alice for RSA public key
s.send("Send me rsa public key".encode())
alice_public_key = int(s.recv(1024).decode())
s.send("Send me rsa n".encode())
alice_n = int(s.recv(1024).decode())

s.settimeout(50)

# Sending Alice Bob's DH public key
if "DH public key" in s.recv(1024).decode():
    s.send(str(encrypt(B, alice_public_key, alice_n)).encode())
    
# Compute shared key 
shared_key = fast_mod_exp(A, b, prime)
print("Shared key: " + str(shared_key))

key = TextToHex(str(shared_key))
key = key_length_handler(key, key_length//4)

aes = AES(key, key_length)

ciphertext = s.recv(1024).decode()
print("Ciphertext: " , ciphertext)
# s.settimeout(100)
num_chunks = int(s.recv(1024).decode())

plaintext = get_decoded_plaintext(aes, num_chunks, ciphertext)
plaintext = bytes.fromhex(plaintext).decode()

print("Plaintext: " + plaintext)

s.send(plaintext.encode())

# close the connection
s.close()    