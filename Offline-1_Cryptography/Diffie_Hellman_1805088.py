import random
die = random.SystemRandom() # A single dice.
import time

def fast_mod_exp(b, exp, m):
    res = 1
    while exp > 1:
        if exp & 1:
            res = (res * b) % m
        b = b ** 2 % m
        exp >>= 1
    return (b * res) % m

def single_test(n, a):
    exp = n - 1
    while not exp & 1:
        exp >>= 1
        
    if fast_mod_exp(a, exp, n) == 1:
        return True
        
    while exp < n - 1:
        if fast_mod_exp(a, exp, n) == n - 1:
            return True
        exp <<= 1
        
    return False
    
def miller_rabin(n, k=40):
    for i in range(k):
        a = die.randrange(2, n - 1)
        if not single_test(n, a):
            return False
            
    return True

def gen_prime(bits):
    bits = bits-1
    while True:
        # Guarantees that a is odd.
        a = (die.randrange(1 << bits - 1, 1 << bits) << 1) + 1
        if miller_rabin(a):
            if miller_rabin((a-1)//2):
                return a
            
def powmod(a, b, p):
    res = 1
    while (b):
        if (b%2==1):
            res = int(res * a % p)
            b = b-1
        else:
            a = int (a * a % p)
            b = int(b) >> 1
    return res

def generator(p):
    phi = p-1
    fact = [2, phi//2] # safe_primes-1 have only two prime factors
    
    for i in range(2, p+1):
        res = random.randint(p//10, p-1)
        ok = True
        for i in range(0, len(fact)):
            if ok:
                ok &= (powmod(res, phi / fact[i], p) != 1)
        if (ok):
            return res
    return -1

def get_private_key(bits_size):
    """
    Sender and receiver selects their secret private keys both at least (k/2) bits long..
    
    Parameters
    ----------

        bits_size: size of large prime in bits
    """
    print("Time taken for calculating sender private key a:", end = " ")
    startTime = time.time()
    sender_private_key = gen_prime((bits_size//2)+1) # a
    print(time.time() -  startTime, end="\n\n")
    
    print("Time taken for calculating receiver private key b:", end = " ")
    startTime = time.time()
    receiver_private_key = gen_prime((bits_size//2)+2) # b
    print(time.time() -  startTime, end="\n\n")
    
    return sender_private_key, receiver_private_key

def get_public_key(g, a, b, p):
    """
    Public keys are A = g^a (mod p) and B = g^b (mod p)
    for sender and receiver respectively
    
    Parameters
    ----------

        p: large prime
        g: generator or primitive root mod p
        a: sender private key
        b: receiver private key
    """
    print("Time taken for calculating sender public key A:", end = " ")
    startTime = time.time()
    sender_public_key = fast_mod_exp(g, a, p) # A
    print(time.time() -  startTime, end="\n\n")
    
    print("Time taken for calculating receiver public key B:", end = " ")
    startTime = time.time()
    receiver_public_key = fast_mod_exp(g, b, p) # B
    print(time.time() -  startTime, end="\n\n")
    
    return sender_public_key, receiver_public_key

def get_shared_key(a, b, A, B, p):
    """
    Both sender and receiver raises the other's public key to the exponent of their
    own private key taking modulo p. So, sender computes B^a (mod p) and receiver
    computes A^b (mod p).
    
    Parameters
    ----------

        p: large prime
        a: sender private key
        b: receiver private key
        A: sender public key
        B: receiver public key
    """
    print("Time taken for calculating shared key:", end = " ")
    startTime = time.time()
    sender_shared_key = fast_mod_exp(B, a, p)
    receiver_shared_key = fast_mod_exp(A, b, p)
    print(time.time() -  startTime, end="\n\n")
    
    if sender_shared_key == receiver_shared_key:
        print("Shared keys are equal")
        print("Shared key: " + str(sender_shared_key))
    else:
        print("Shared keys are not equal")


# prime_bits = int(input("No. of bits of prime no.: "))

# print("Time taken for calculating prime number p:", end = " ")
# startTime = time.time()
# prime = gen_prime(prime_bits)
# print(time.time()-startTime, end="\n\n")

# print("Time taken for calculating primitive root g:", end = " ")
# startTime = time.time()
# prim_root = generator(prime)
# print(time.time() - startTime, end="\n\n")
# # print(prim_root)

# a, b = get_private_key(prime_bits)

# A, B = get_public_key(prim_root, a, b, prime)

# get_shared_key(a, b, A, B, prime)