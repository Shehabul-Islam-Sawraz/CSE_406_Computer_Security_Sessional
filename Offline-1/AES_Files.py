from AES import *
import os

def file_to_hex(file_name):
    try:
        with open(file_name, 'rb') as file:
            data = file.read()
            hex_data = data.hex()
            return hex_data
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
        return None
    
def hex_to_file(hex_data, file_name):
    try:
        with open(file_name, 'wb') as file:
            file.write(bytes.fromhex(hex_data))
        print(f"File '{file_name}' created successfully.")
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
    except ValueError:
        print("Invalid hexadecimal data.")
    

file_name = input("Enter File Name: ")
plaintext = file_to_hex(file_name)

if plaintext is None:
    exit()

filename, extension = os.path.splitext(file_name)

key_length = int(input("Length of key in bits: "))
key = input("Key in ASCII: ")
key = TextToHex(key)
key = key_length_handler(key, key_length//4)

aes = AES(key, key_length) # Initializing AES

startTime = time.time()
ciphertext = get_ciphertext(aes, plaintext_handler(plaintext))
print(f'Encryption time: {time.time() - startTime} seconds')

startTime = time.time()
decoded_plaintext = get_decoded_plaintext(aes, len(plaintext)//32, ciphertext)
print(f'Decryption time: {time.time() - startTime} seconds')

hex_to_file(decoded_plaintext, filename+"_decrypted"+extension)