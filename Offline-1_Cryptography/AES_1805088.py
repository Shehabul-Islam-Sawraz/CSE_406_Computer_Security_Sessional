from BitVector import *
import time

class AES:
    """
    A class used to encapsulate every method and 
    attribute necessary to encrypt with AES algorith. 
    
    Attributes
    ----------

    Sbox : tuple
        Substitution table used in the SubBytes operation
    InvSbox : tuple 
        Substitution table used in the InvSubBytes operation
    Rcon: tuple
        Round constant table used in rounding every 4th word
    Nr : int
        Number of rounds
    Nc : int
        Number of columns of 32-bit words comprising the State
    Nw : int
        Number of 32-bit words comprising the Cipher Key
    """
    
    Nr = 10
    
    Nc = 4

    Nw = 4

    Sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    InvSbox = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )
    
    Rcon = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )
    
    MixCols = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    InvMixCols = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]
    
    def text2matrix(self, text, len=16):
        """
        Transforms a 128/192/256 bit block written in plain text form to the State Matrix form of Integer values.

        Parameters
        ----------

        text : string
            128 bit block in plain text
        """
        state = []

        for i in range(len):
            # two hex characters == 1 byte
            byte = int(text[i*2:i*2+2], 16)
            # print(byte)
            if i % 4 == 0:
                # this means that the byte to append is the first of the column
                state.append([byte])
            else:
                # Append byte to the row i // 4 
                state[i // 4].append(byte) 

        return state
    
    def matrix2text(self, state, len=16):
        """
        Transforms a 128/192/256 bit block written in State form into plain text.

        Parameters
        ----------

        s : matrix
            State
        """
        text = ""
        for i in range(len // 4):
            for j in range(4):
                text += format(state[i][j], '02x')

        return text
    
    def rotate_word(self, w):
        """
        Take a four-byte word and performs a cyclic
        permutation.

        Parameters
        ----------
        w : Word
        """

        w[0], w[1], w[2], w[3] = w[1], w[2], w[3], w[0]
        
    def sub_word(self, w):
        """
        Take a four-byte word and applies the S-Box

        Parameters
        ----------
        w : Word 
        """
        for i in range(len(w)):
            w[i] = self.Sbox[w[i]]
            
    def sub_bytes(self, state):
        """
        Replaces the values in the State matrix with values in S-Box

        Parameters
        ----------

        s : matrix
            State
        """
        for i in range(self.Nc):
            for j in range(4):
                state[i][j] = self.Sbox[state[i][j]]
                
    def inv_sub_bytes(self, state):
        """
        Replaces the values in the State matrix with Values in Inv S-Box

        Parameters
        ----------

        s : matrix
            State
        """
        for i in range(self.Nc):
            for j in range(4):
                state[i][j] = self.InvSbox[state[i][j]]
            
    def add_round_key(self, state, key):
        """
        Add round key to the State.

        Parameters
        ----------
        
        s : matrix
            State

        k : matrix
            Key

        """
        for i in range(self.Nc):
            for j in range(4):
                state[i][j] ^= key[i][j]
                
    def shift_rows(self, s):
        """
        Shifts cyclically the bytes of the last three rows.

        Parameters
        ----------

        s : matrix
            State
        """

        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
        
    def inv_shift_rows(self, s):
        """
        Shifts cyclically the bytes of the last three rows. It's 
        the inverse of shift_rows().

        Parameters
        ----------

        s : matrix
            State
        """

        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
        
    def bit_mult(self, a, b):
        AES_modulus = BitVector(bitstring='100011011')
        bv1 = BitVector(intVal = a, size = 8)
        bv2 = BitVector(intVal = b, size = 8)
        bv3 = bv1.gf_multiply_modular(bv2, AES_modulus, 8)
        return int(bv3)

    def mix_one_column(self, c, type):
        x = [0, 0, 0, 0]
        for i in range(self.Nc):
            x[i]=0
            # print(c, self.InvMixCols[i])
            for j in range(self.Nc):
                if type=="encrypt":
                    x[i] = x[i]^(self.bit_mult(self.MixCols[i][j], c[j]))
                else:
                    x[i] = x[i]^(self.bit_mult(self.InvMixCols[i][j], c[j]))
        for i in range(self.Nc):
            c[i] = x[i]

    def mix_columns(self, s, type="encrypt"):
            """
            Mix columns.

            Parameters
            ----------

            s : matrix
                State
            """

            for i in range(self.Nc):
                self.mix_one_column(s[i], type)
                
    def inv_mix_columns(self, s):
            self.mix_columns(s, "decrypt")
    
    def key_expansion(self, key):
        """
        Takes the Cipher Key and performs a Key Expansion.

        Parameters
        ----------

        key : string
            Cipher Key in string format.
        """        

        self.round_keys = self.key # We have round key for round 0

        for i in range(self.Nw, self.Nc * (self.Nr + 1)): # Generate round key for round 1 to 10
            self.round_keys.append([0, 0, 0, 0])
            temp = self.round_keys[i - 1][:]
            # word is multiple of Nw
            # Calculating g(w[3]) or g(w[7]) or ......
            if i % self.Nw == 0: # if w[4]/w[8]/w[12]/....
                self.rotate_word(temp) # circular byte left shift of w[3]/w[7]/.....
                self.sub_word(temp) # Byte substitution (S-Box)
                temp[0] = temp[0] ^ self.Rcon[i // self.Nw] # Adding round constant
            elif self.Nw > 6 and i % self.Nw == 4:
                """If Nw = 8 (AES-256) and i - 4 is multiple of Nw
                then SUbWord() is applied to word[i - 1] prior to
                the XOR. Nist Fips 192."""
                self.sub_word(temp)

            for j in range(4):
                self.round_keys[i][j] = self.round_keys[i - self.Nw][j] ^ temp[j]

    def cipher(self, text):
        """
        Ciphers the given text with the key given in the class
        constructor.

        Parameters
        ----------

        text : string
            128 bit block in plain text.

        Returns
        -------

        encrypted_text : string
            128 bit block in plain text encrypted with the key expecified
            in the class constructor.
        """
        
        self.state = self.text2matrix(text)

        self.add_round_key(self.state, self.round_keys[:4])
    
        for i in range(1, self.Nr):
            self.sub_bytes(self.state)
            self.shift_rows(self.state)
            self.mix_columns(self.state)
            self.add_round_key(self.state, self.round_keys[self.Nc * i : self.Nc * (i + 1)])

        self.sub_bytes(self.state)
        self.shift_rows(self.state)
        self.add_round_key(self.state, self.round_keys[len(self.round_keys) - 4:])

        return self.matrix2text(self.state)
    
    def decipher(self, text):
        """
        Deciphers the given encrypted text with the key given 
        in the class constructor.

        Parameters
        ----------

        text : string
            128 bit block in plain text.

        Returns
        -------

        decrypted_text : string
            128 bit block in plain text decrypted with the key given
            in the class constructor.
        """

        self.encrypted_state = self.text2matrix(text)
        
        self.add_round_key(self.encrypted_state, self.round_keys[len(self.round_keys) - 4:])

        for i in range(self.Nr - 1, 0, -1):
            self.inv_shift_rows(self.encrypted_state)
            self.inv_sub_bytes(self.encrypted_state)
            self.add_round_key(self.encrypted_state, self.round_keys[self.Nc * i : self.Nc * (i + 1)])
            self.inv_mix_columns(self.encrypted_state)

        self.inv_shift_rows(self.encrypted_state)
        self.inv_sub_bytes(self.encrypted_state)
        self.add_round_key(self.encrypted_state, self.round_keys[:4])

        return self.matrix2text(self.encrypted_state)
    
    def __init__(self, key, mode=128):
        if mode == 192:
            self.Nw = 6
            self.Nr = 12
            self.key = self.text2matrix(key, 24)
        elif mode == 256:
            self.Nw = 8
            self.Nr = 14
            self.key = self.text2matrix(key, 32)
        else:
            self.key = self.text2matrix(key)

        self.key_expansion(self.key)
        
def TextToHex(text):
    return text.encode().hex() # Convert text to hex

def pad(block, block_length):
    """
    Pads a block with padding bytes to make it
    to the required length, in this case, 128 bits.

    PKCS5 padding
    
    Parameters
    ----------

    block : string
        Block to be padded written in hexadecimal as string.

    block_length : int
        Block length in bytes.

    Returns
    
    -------
    block : string
        Block padded
    """
    bytes_to_pad = (block_length - len(block)) // 2

    for _ in range(bytes_to_pad):
        block += format(bytes_to_pad, '02x')

    return block

def unpad(block):
    """
    Unpads a block padded with pad() method.

    Parameters
    ----------

    block : string
        Block to be unpadded written in hexadecimal as string.


    Returns
    -------
    
    block : string
        Block padded
    """
    bytes_to_unpad = int(block[-2:], 16)
    return block[:-bytes_to_unpad*2]

def key_length_handler(key, key_length):
    # Handling key length
    # Key length = num of hex digits
    if len(key)<key_length:
        key = pad(key, key_length)
    elif len(key)>key_length:
        key = key[0:key_length]
        
    # print(key)
    return key

def plaintext_handler(plaintext):
    plaintext_chunks = []
    num_chunks = len(plaintext)//32

    for i in range(num_chunks):
        plaintext_chunks.append(plaintext[i*32:(i+1)*32])
    if (len(plaintext)%32) !=0:
        plaintext_chunks.append(pad(plaintext[num_chunks*32:len(plaintext)], 32))

    # print(plaintext_chunks)    
    return plaintext_chunks

def get_ciphertext(aes, plaintext_chunks):
    ciphertext = ""
    for i in range(len(plaintext_chunks)):
        ciphertext += aes.cipher(plaintext_chunks[i])

    # print(ciphertext)
    return ciphertext

def get_decoded_plaintext(aes, num_chunks, ciphertext):
    decoded_plaintext = ""
    for i in range(num_chunks):
        decoded_plaintext += aes.decipher(ciphertext[i*32:(i+1)*32])
        
    if (len(ciphertext)//32) !=num_chunks:
        decoded_plaintext += unpad(aes.decipher(ciphertext[num_chunks*32:len(ciphertext)]))
            
    return decoded_plaintext

# key_length = int(input("Length of key in bits: "))
# key = input("Key in ASCII: ")
# key = TextToHex(key)
# print("Key in Hex: " + key)
# key = key_length_handler(key, key_length//4)

# startTime = time.time()
# aes = AES(key, key_length) # Initializing AES
# print(f'Key scheduling: {time.time() - startTime} seconds')

# plaintext = input("\nPlain Text in ASCII: ")
# plaintext = TextToHex(plaintext)
# print("Plain Text in Hex: " + plaintext)

# startTime = time.time()
# ciphertext = get_ciphertext(aes, plaintext_handler(plaintext))
# print("\nCipher Text: ")
# print("In Hex: " + ciphertext)
# # print("In ASCII: " + bytes.fromhex(ciphertext).decode())
# print(f'Encryption time: {time.time() - startTime} seconds')

# startTime = time.time()
# decoded_plaintext = get_decoded_plaintext(aes, len(plaintext)//32, ciphertext)
# print("\nDeciphered Text: ")
# print("In Hex: " + decoded_plaintext)
# print("In ASCII: " + bytes.fromhex(decoded_plaintext).decode())
# print(f'Decryption time: {time.time() - startTime} seconds')