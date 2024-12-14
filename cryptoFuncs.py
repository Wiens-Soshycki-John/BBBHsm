#for server and db
from flask import Flask, request, jsonify, render_template
import sqlite3
import traceback
from cryptography.hazmat.backends import default_backend

#for symmetric key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import algorithms
import os
import base64

#for asymmetric key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

#for encryption
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

#DB_NAME = 'key_storage.db'
DB_NAME = 'test_storage4.db'

##################################### 
#importing re and creating is_valid_base64 in response to debugging verifying
#most testing was done with curl statements, after much research we noticed or 
#signature was considered a valid base 64 object with proper padding
#while returning from sign but not when entering verifying, we believe there is 
#some error happening during the function call
import re
def is_valid_base64(s):
    pattern = r'^[A-Za-z0-9+/]*={0,2}$'
    return bool(re.fullmatch(pattern, s))
#####################################




#####################################
def get_db_connection():
    return sqlite3.connect(DB_NAME)
######################################



######################################
def create_symmetric_key():
    #note this function is designed to generate keys for symmetric use
    #use operating system to generate a 256 bit AES key
    key = os.urandom(32)  

    #connect to db to update and add the key
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM keys")
    key_count = c.fetchone()[0]
    key_id = f"key_{key_count + 1}" 

    c.execute("INSERT INTO keys (key_id, key_blob, key_type) VALUES (?, ?, ?)",
                          (key_id, key, 'SYMMETRIC'))
    #apply changes
    conn.commit()
    conn.close()

    return key_id
######################################



######################################
def create_Asymmetric_key():
    #this function is specifically meant for creating asymmetric key pairs
    #1024 is half the standard size
    lengOfKey=2048
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM keys")
    key_count = c.fetchone()[0]
    key_id = f"key_{key_count + 1}"

    #asymmetric keys need two keys generate bounded by the sharing of
    #a common n where n=p1*p2 two prime numbers, the other values of each
    #b and c when multipled will =mod(theta(n)) where theta(n)=(p1-1)*(p2-1)
    privKey = rsa.generate_private_key(public_exponent=65537, key_size=lengOfKey )
    pubKey = privKey.public_key()

    #code below serializes the private and public key into pem format
    privKey_pem = privKey.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
    pubkey_pem = pubKey.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    # Store the private key in the database with type 'RSA_PRIVATE'
    c.execute("INSERT INTO keys (key_id, key_blob, key_type) VALUES (?, ?, ?)",
            (key_id, privKey_pem, 'RSA_PRIVATE'))    
    #store the public key in database with type 'RSA_PUBLIC'
    c.execute("INSERT INTO keys (key_id, key_blob, key_type) VALUES (?, ?, ?)",
        (f"{key_id}_pub", pubkey_pem, 'RSA_PUBLIC'))
            
    #apply changes
    conn.commit()
    conn.close()

    return key_id
######################################



######################################
def encrypt(data, key_id):
    #encryption supported for symmetric keys, had too many issues with asymmetric keys
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key_blob, key_type FROM keys WHERE key_id=?", (key_id,))
    result = c.fetchone()
    conn.close()
    if result is None:
        raise ValueError("Key not found")

    key_blob,key_type = result
    if key_type != 'SYMMETRIC':
            raise ValueError("Wrong type of key for encryption")
    
    

    #key_blob = base64.b64decode(key_blob)
    assert len(key_blob) == 32, f"Invalid key length: {len(key_blob)}"
    #initialization vector adds randomness to the first encrypted block of the cipher
    iv = os.urandom(16)
    #initializing the encryptor
    #AES algorithm used for encryption .CBC mode makes uses of the IV
    cipher = Cipher(algorithms.AES(key_blob), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    #pad text to be a multiple of 16 bytes for aes
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(str(data).encode('utf-8')) + padder.finalize()

    #encrypting the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_data_with_iv = iv + encrypted_data

    #base64 will converted encryption from binary to a string representation for our database
    encrypted_data_b64 = base64.b64encode(encrypted_data_with_iv).decode('utf-8')
    return encrypted_data_b64
######################################



######################################
def decrypt(key_id, encrypted_data_b64):
    #ensure proper padding
    if len(encrypted_data_b64) % 4 != 0:
        encrypted_data_b64 += '=' * (4 - len(encrypted_data_b64) % 4)

    # Decode Base64 encrypted data
    encrypted_data = base64.b64decode(encrypted_data_b64)
    print(f"Decoded encrypted_data: {repr(encrypted_data)}")


    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data length")

    # Retrieve the key from the database
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT key_blob, key_type FROM keys WHERE key_id=?", (key_id,))
    result = c.fetchone()
    conn.close()

    if result is None:
        raise ValueError("Key not found")

    key_blob, key_type = result
    if key_type != 'SYMMETRIC':
        raise ValueError("Wrong key type for decryption")
        

    # Extract IV and ciphertext
    if len(encrypted_data) < 16:
        raise ValueError("Invalid encrypted data length")
        

    iv = encrypted_data[:16]  # First 16 bytes: IV
    ciphertext = encrypted_data[16:]  # Remaining bytes: ciphertext
    print(f"IV: {iv}")
    print(f"Ciphertext: {ciphertext}")

    # Initialize decryptor
    cipher = Cipher(algorithms.AES(key_blob), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext.decode('utf-8')
######################################    



######################################
def sign(key_name, message):
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key_blob, key_type FROM keys WHERE key_id = ?", (key_name,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise ValueError("Key not found")

    key_blob, key_type = row
    if key_type != 'RSA_PRIVATE':
        raise ValueError("Key not of type: RSA_Private")
        

    private_key = serialization.load_pem_private_key(key_blob, password=None, backend=default_backend())
    signature = private_key.sign(
        str(message).encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    #if all went correct the signature should not raise any errors
    try:
        base64.b64decode(signature_b64)  
    except Exception as e:
        raise ValueError(f"Error in Base64 encoding/decoding: {e}")
    return signature_b64
######################################



######################################
def verify(key_name, message, signature_b64):
     # Ensure valid Base64, this was used in testing to compare to the try and except
     #statement above, for reasons as of submission we don't understand
     #identical signatures will pass the first but not the second, our best assumption
     #is that the data is corrupted when mainly copying and pasting the signature
     #as an argument in our tests
    try:
        base64.b64decode(signature_b64)  
    except Exception as e:
        raise ValueError(f"Error in Base64 encoding/decoding: {e}")
    # Ensure valid Base64
 

    if len(signature_b64) % 4 != 0:
        signature_b64 += '=' * (4 - len(signature_b64) % 4)
    
    if not is_valid_base64(signature_b64):
        raise ValueError("Invalid Base64 string")
        

    # Decode the signature
    try:
        signature = base64.b64decode(signature_b64)
    except Exception as e:
        raise ValueError(f"Failed to decode Base64 signature: {e}")

    # Retrieve the public key from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key_blob, key_type FROM keys WHERE key_id = ?", (key_name,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise ValueError("Key not found")

    key_blob, key_type = row
    if key_type != 'RSA_PUBLIC':
        raise ValueError("Invalid key type for verification")

    
    #key_blobs arent base64 encoded into pem files, no need to decode
    # Load the public key
    public_key = serialization.load_pem_public_key(key_blob, backend=default_backend())

    # Verify the signature
    try:
        public_key.verify(
            signature,
            str(message).encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        #if verification fails and exception is made and therefore there is no need for 
        #if else statements and invidiual return statements

        
        return "Signature is valid"
    except Exception as e:
        return "Signature is not valid"
######################################



######################################
def destroy(key_id):
    conn = get_db_connection()
    c = conn.cursor()
    
    # Delete both private and public keys by checking for the key_id and its public counterpart
    c.execute("DELETE FROM keys WHERE key_id=? OR key_id=?", (key_id, f"{key_id}_pub"))
    conn.commit()
    conn.close()
    return f"Successfully destroyed key pair: {key_id}"
######################################
    