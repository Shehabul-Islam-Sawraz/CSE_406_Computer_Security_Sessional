import random
import math
die = random.SystemRandom() # A single dice.
from hashlib import sha512

class RSA:
    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a
    
    def extended_gcd(self, a, b):
        if b == 0:
            return a, 1, 0
        gcd, x1, y1 = self.extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return gcd, x, y

    def modular_inverse(self, a, m):
        gcd, x, y = self.extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    def is_prime(self, n, k=40):
        # Miller-Rabin primality test
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = fast_mod_exp(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = fast_mod_exp(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def find_coprime(self, n):
        while True:
            potential_coprime = random.randint(2, n - 1)
            if self.gcd(n, potential_coprime) == 1 and self.is_prime(potential_coprime):
                return potential_coprime
            
    def gen_prime(self, bits):
        bits = bits-1
        while True:
            # Guarantees that a is odd.
            a = (die.randrange(1 << bits - 1, 1 << bits) << 1) + 1
            if self.is_prime(a):
                return a
            
    def generate_public_key(self):
        # Choose a co-prime between 1 & phi
        e = self.find_coprime(self.phi)
        
        return e, self.n
    
    def generate_private_key(self, public_key):
        # Compute d, the modular multiplicative inverse of e (mod phi)
        d = self.modular_inverse(public_key, self.phi)
        
        return d
    
    def __init__(self, key_size):
        # Choose two distinct prime numbers
        self.p = self.gen_prime(key_size)
        self.q = self.gen_prime(key_size+1)
        
        # Compute n = pq
        self.n = self.p*self.q
        
        self.phi = (self.p-1)*(self.q-1)
   
def fast_mod_exp(b, exp, m):
        res = 1
        while exp > 1:
            if exp & 1:
                res = (res * b) % m
            b = b ** 2 % m
            exp >>= 1
        return (b * res) % m
    
def encrypt(message, public_key, n):
        return fast_mod_exp(message, public_key, n)
    
def decrypt(ciphertext, private_key, n):
    return fast_mod_exp(ciphertext, private_key, n)

def sign(message, private_key, n):
    hash = int.from_bytes(sha512(message).digest(), byteorder='big')
    signature = fast_mod_exp(hash, private_key, n)
    return signature

def verify(message, signature, public_key, n):
    hashFromSignature = fast_mod_exp(signature, public_key, n)
    return hashFromSignature == message

   
def plaintext_to_integer(plaintext):
    integer_representation = 0
    for char in plaintext:
        integer_representation = integer_representation * 128 + ord(char)
    return integer_representation

def integer_to_plaintext(integer_representation):
    plaintext = ""
    while integer_representation > 0:
        char_code = integer_representation % 128
        plaintext = chr(char_code) + plaintext
        integer_representation //= 128
    return plaintext
        
# key_size = int(input("Length of key in bits: "))
# rsa = RSA(key_size)

# plaintext = input("\nPlain Text in ASCII: ")
# plaintext = plaintext_to_integer(plaintext)
# print("Plain Text in integer: " + str(plaintext))

# public_key, n = rsa.generate_public_key()
# private_key = rsa.generate_private_key(public_key)

# ciphertext = encrypt(plaintext, public_key, n)
# print("Cipher Text in integer: " + str(ciphertext))

# decrypted_plaintext = decrypt(ciphertext, private_key, n)
# print("Decrypted Text in integer: " + str(decrypted_plaintext))
# print("Decrypted Text: " + integer_to_plaintext(decrypted_plaintext))


