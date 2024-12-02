#for symmetric key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import algorithms
import os
import base64

#for asymmetric key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

######################################
def create_Key(password, lengOfKey):
    
    #hasing algorithm, given an input we pad it to 512 bits, chop the padded
    #version up and apply multiple bitwise operations, 64 in this case
    #to avalanche effect a unique irreversible key id

    #only doing 5000 iterations of hashing instead of 10000 standard
    #to reduce load on our poor Beable Board :(
   

    #init keyDerivFunc
    keyDerivFunc = PBKDF2HMAC(algorithm=hashes.SHA256(),length=lengOfKey,salt=os.urandom(16),
                              iterations=5000)
    #gen key, why 64, not exactly sure myself
    key64 = base64.b64encode(keyDerivFunc.derive(password))
    print("Generated Key:", key64.decode('utf-8'))
    return key64
######################################

######################################
def create_ASymKey(lengOfKey):
    #asymmetric keys need two keys generate bounded by the sharing of
    #a common n where n=p1*p2 two prime numbers, the other values of each
    #b and c when multipled will =mod(theta(n)) where theta(n)=(p1-1)*(p2-1)
    privKey = rsa.generate_private_key(public_exponent=65537, key_size=lengOfKey)
    pubKey = privKey.public_key()

    #private key is for encryption (only on server), public is for decryption(can provide to user)
    keyPair = [privKey, pubKey]
    return keyPair
######################################

######################################
def encrypt():
    return 0
######################################

def decrypt():
    return 0

def sign():
    return 0

def vertify():
    return 0


def store():
    return 0