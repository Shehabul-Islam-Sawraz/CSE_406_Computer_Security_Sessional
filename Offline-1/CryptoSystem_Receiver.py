# Import socket module
import socket       
from Diffie_Hellman import *
from AES import *

key_length = 128     
 
# Create a socket object
s = socket.socket()        
 
# Define the port on which you want to connect
port = 1337               
 
# connect to the server on local computer
s.connect(('127.0.0.1', port))
 
# receive data from the server and decoding to get the string.
s.send("Send prime number".encode())
prime = int(s.recv(1024).decode())

s.send("Send generator".encode())
gen = int(s.recv(1024).decode())

# Sharing public key of BOB
b = gen_prime((key_length//2)+2)
print("Private Key: " + str(b))
B = fast_mod_exp(gen, b, prime)
print("Public Key: " + str(B))

s.send("Send your public key".encode())
# Receive sender public key
A = int(s.recv(1024).decode())

if "key" in s.recv(1024).decode():
    s.send(str(B).encode())
    
# Compute shared key 
shared_key = fast_mod_exp(A, b, prime)
print("Shared key: " + str(shared_key))

key = TextToHex(str(shared_key))
key = key_length_handler(key, key_length//4)

aes = AES(key, key_length)

ciphertext = s.recv(1024).decode()
num_chunks = int(s.recv(1024).decode())

plaintext = get_decoded_plaintext(aes, num_chunks, ciphertext)
plaintext = bytes.fromhex(plaintext).decode()

print("Plaintext: " + plaintext)

s.send(plaintext.encode())

# close the connection
s.close()    