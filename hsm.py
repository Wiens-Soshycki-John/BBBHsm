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

hsm = Flask(__name__)
DB_NAME = 'key_storage.db'
######################################
def init_db():
    #uses sqlite3 for db architecture, this func make sure it exists when the HSM runs
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    key_blob BLOB,
                    key_type TEXT)''')
    conn.commit()
    conn.close()

#####################################

#run init_db for safe measure
init_db()


#####################################
def get_db_connection():
    return sqlite3.connect(DB_NAME)
######################################



######################################
@hsm.route('/')
def home():
    return render_template('index.html')
######################################



######################################
@hsm.route('/create_key', methods=['GET', 'POST'])
def create_Key():
    if request.method == 'POST':
        try:        
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
            return jsonify({'message': f'Key {key_id} created successfully'}), 200
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error: {error_message}")
            return jsonify({'error': f'Error: {error_message}'}), 500
    else:
        return render_template('create_key.html')
######################################



######################################
@hsm.route('/create_ASymKey', methods=['GET', 'POST'])
def create_ASymKey():
    lengOfKey = 1024
    if request.method == 'POST':
        try:
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

            #code belowserializes the private and public key into pem format
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

            return jsonify({'message': f'Key {key_id} created successfully'}), 200        
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error: {error_message}")
            return jsonify({'error': f'Error: {error_message}'}), 500
    else:
        return render_template('create_key.html')
######################################



######################################
@hsm.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'GET':
        return render_template('encrypt.html')
    # POST logic remains the same
    key_id = request.form.get('key_id') 
    data = request.form.get('data')
    if not key_id or not data:
        return jsonify({'error': 'Key ID and data are required'}), 400
    try:
        #preparing the database to retrieve a key
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT key_blob, key_type FROM keys WHERE key_id=?", (key_id,))
        result = c.fetchone()
        conn.close()
        if result is None:
            return jsonify({'error': 'Key not found'}), 404

        key_blob, key_type = result
        if key_type != 'SYMMETRIC':
            return jsonify({'error': 'Invalid key type for encryption'}), 400

        assert len(key_blob) == 32, "Invalid key length"
        #initialization vector adds randomness to the first encrypted block of the cipher
        iv = os.urandom(16)
        #initializing the encryptor
        #AES algorithm used for encryption .CBC mode makes uses of the IV
        cipher = Cipher(algorithms.AES(key_blob), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        #pad text to be a multiple of 16 bytes for aes
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        #encrypting the data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_data_with_iv = iv + encrypted_data

        #base64 will converted encryption from binary to a string representation for our database
        encrypted_data_b64 = base64.b64encode(encrypted_data_with_iv).decode('utf-8')
        return jsonify({'encrypted_data': encrypted_data_b64}), 200
    except Exception as e:
        print(f"Error in encryption: {e}")
        return jsonify({'error': 'Error: Unable to encrypt data'}), 500
######################################



######################################
'''
@hsm.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'GET':
        return render_template('decrypt.html')
    # POST logic remains the same
    #request key id for decryption, will find later from the db
    key_id = request.form.get('key_id')
    #request encrypted data
    encrypted_data = request.form.get('encrypted_data')
    if not key_id or not encrypted_data:
        return jsonify({'error': 'Key ID and encrypted data are required'}), 400

    try:
        encrypted_data_64 = encrypted_data
        print("attempting to intercept code")
        if len(encrypted_data_64) % 4 != 0:
                print("Encrypted data wasn't base 64")
                encrypted_data_64 += '=' * (4 - len(encrypted_data_64) % 4)
        encrypted_data = base64.b64decode(encrypted_data_64)
        print("encrypted data recieved")
        #retrieving the key used for decryption from db
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT key_blob, key_type FROM keys WHERE key_id=?", (key_id,))
        result = c.fetchone()
        conn.close()

        if result is None:
            return jsonify({'error': 'Key not found'}), 404

        key_blob, key_type = result
        if key_type != 'SYMMETRIC':
            return jsonify({'error': 'Invalid key type for decryption'}), 400

        if len(encrypted_data) < 16:
            return jsonify({'error': 'Invalid encrypted data length'}), 400
        print("Base64-decoded data:", encrypted_data)
        #extract the iv from the encrypted data, which will be neccesaary for the ciphers' decryptor
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        #have cipher create a decryptor for AES
        cipher = Cipher(algorithms.AES(key_blob), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        #retrieve decrypted data, and clean data padded on
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return jsonify({'decrypted_data': plaintext.decode('utf-8')}), 200
    except Exception as e:
        print(f"Error in decryption: {e}")
        return jsonify({'error': 'Error: Unable to decrypt data'}), 500
######################################    
'''

@hsm.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Extract inputs
        key_id = request.form.get('key_id')
        encrypted_data_b64 = request.form.get('encrypted_data')

        if not key_id or not encrypted_data_b64:
            return jsonify({'error': 'Key ID and encrypted data are required'}), 400
        
        

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
            return jsonify({'error': 'Key not found'}), 404

        key_blob, key_type = result
        if key_type != 'SYMMETRIC':
            return jsonify({'error': 'Invalid key type for decryption'}), 400

        # Extract IV and ciphertext
        if len(encrypted_data) < 16:
            return jsonify({'error': 'Invalid encrypted data length'}), 400

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

        return jsonify({'decrypted_data': plaintext.decode('utf-8')}), 200
    except Exception as e:
        print(f"Error in decryption: {e}")
        return jsonify({'error': 'Error: Unable to decrypt data'}), 500


######################################
@hsm.route('/sign', methods=['GET', 'POST'])
def sign():
    if request.method == 'GET':
        return render_template('sign.html')
    # POST logic remains the same
    key_name = request.form.get('key_name')
    message = request.form.get('message')

    if not key_name or not message:
        return jsonify({'error': 'Key name and message are required'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT key_blob, key_type FROM keys WHERE key_id = ?", (key_name,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'Key not found'}), 404

        key_blob, key_type = row
        if key_type != 'RSA_PRIVATE':
            return jsonify({'error': 'Invalid key type for signing'}), 400

        private_key = serialization.load_pem_private_key(key_blob, password=None, backend=default_backend())
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        return jsonify({'signature': signature_b64}), 200
    except Exception as e:
        print(f"Error in signing: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500

def verify():
    return 0

@hsm.route('/destroy_key', methods=['GET', 'POST'])
def destroy_key():
    if request.method == 'POST':
        key_id = request.form.get('key_id')
        if not key_id:
            return jsonify({'error': 'Key ID is required'}), 400
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM keys WHERE key_id=?", (key_id,))
            conn.commit()
            conn.close()
            return jsonify({'message': f'Key {key_id} destroyed successfully'}), 200
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({'error': 'Error: Unable to destroy key'}), 500
    else:
        return render_template('destroy_key.html')

if __name__ == '__main__':
    hsm.run(host='0.0.0.0', port=5000, debug=True)