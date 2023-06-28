import socket   
from Diffie_Hellman import *  
from AES import *
 
key_length = 128
 
# next create a socket object
print("This is Alice")
s = socket.socket()        
print ("Socket successfully created")
 
# reserve a port on your computer in our
# case it is 1337 but it can be anything
port = 1337               
 
# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))        
print ("socket binded to %s" %(port))
 
# put the socket into listening mode
s.listen(5)    
print ("socket is listening")           
 
# a forever loop until we interrupt it or
# an error occurs
 
# Establish connection with client.
c, addr = s.accept()    
print ('Got connection from', addr )

# send a thank you message to the client. encoding to send byte type.
# Share prime & generator
prime = gen_prime(key_length)
gen = generator(prime)
print("Prime: " + str(prime))
print("Generator: " + str(gen))

if "prime" in c.recv(1024).decode():
    c.send(str(prime).encode())
    
if "generator" in c.recv(1024).decode():
    c.send(str(gen).encode())
  
# Sharing public key of Alice
a = gen_prime((key_length//2)+1)
print("Private Key: " + str(a))
A = fast_mod_exp(gen, a, prime)
print("Public Key: " + str(A))

if "key" in c.recv(1024).decode():
    c.send(str(A).encode())
    
# Signal BOB to send BOB's public key
c.send("Send me public key".encode())

B = int(c.recv(1024).decode())
print("BOB pubic key received: " + str(B))


# Compute shared key
shared_key = fast_mod_exp(B, a, prime)
print("Shared key: " + str(shared_key))

plaintext = "One Two Three Four Five Six Seven Eight"
plaintext = TextToHex(plaintext)

key = TextToHex(str(shared_key))
key = key_length_handler(key, key_length//4)

aes = AES(key, key_length)

ciphertext = get_ciphertext(aes, plaintext_handler(plaintext))

c.send(ciphertext.encode())
c.send(str(len(plaintext)//32).encode())

decoded_plaintext = c.recv(1024).decode()
# print(decoded_plaintext)

if TextToHex(decoded_plaintext) == plaintext:
    print("Successful")
else:
    print("Falied")

c.close()
s.close()

  