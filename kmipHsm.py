#for server and db and flask
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


#kmip related imports
import kmip
from kmip.services.server import KmipServer




from kmip.core import exceptions as kmip_exceptions
from kmip.core.enums import Operation

#payloads for request
from kmip.core.messages.payloads.encrypt import EncryptRequestPayload
from kmip.core.messages.payloads.encrypt import EncryptResponsePayload

#our cryptography implementation
from cryptoFuncs import *

kmipHsm = Flask(__name__)
DB_NAME = 'test_storage4.db'

######################################
#these functions were temporary functions for quickly checking
#the feasibility of create two threads for our ports
#in the end since we had issues with the kmip_server it ended up 
#not being used
import threading
def start_flask():
    init_db()
    kmipHsm.run(host="127.0.0.1", port=5000, debug=True)

def start_kmip():
    kmip_server = KmipServer(
        hostname="127.0.0.1",
        port=5696,  
        certificate_path="certificate.pem",
        key_path="private_key.pem",
        ca_path="certificate.pem",
        database_path=DB_NAME,
        config_path="server.conf"
    )
    with kmip_server:
        kmip_server.serve()
######################################







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

#run init_db to allow crypto operations to connect to
init_db()

#####################################
def get_db_connection():
    return sqlite3.connect(DB_NAME)
######################################

######################################
#this class was created in place of kmip.exceptions which was having some issues
class KmipOperationError(Exception):
    def __init__(self, message):
        super().__init__(message)
######################################








######################################
##FLASK ROUTES TO FUNCTIONS
######################################
#Flask enpoints, not much to cover here, each one is encapsulated in a try and except
#statement for error handling and simply call the core cryptographic operations we
#have implemented in cryptoFuncs.py

#we originally decoupled this functionality in preparation of supporting kmips
#endpoints which in the end we couldn't implement properly


######################################
@kmipHsm.route('/')
def home():
    return render_template('index.html')
######################################  



######################################
@kmipHsm.route('/create_key', methods=['GET', 'POST'])
def create_symkey_route():
    if request.method == 'POST':

        """Flask route to create a symmetric key."""
        try:
            key_id = create_symmetric_key()  #call from cryptoFuncs symmetric key generation
            return render_template('createKey.html', key_id=key_id)
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error: {error_message}")
            return jsonify({'error': f'Error: {str(e)}'}), 500
    if request.method == 'GET':
        return render_template('createKey.html')
#######################################



#######################################
@kmipHsm.route('/create_Asymkey', methods=['GET', 'POST'])
def create_Asym_route():
    if request.method == 'POST':
        """Flask route to create an Asymmetric key."""
        try:
            key_id = create_Asymmetric_key() #call from cryptoFuncs asymmetric key generation
            return render_template('createKey.html', key_id=key_id)
        except Exception as e:
            error_message = traceback.format_exc()
            print(f"Error: {error_message}")
            return jsonify({'error': f'Error: {str(e)}'}), 500
    return render_template('createKey.html')
#######################################



#######################################
@kmipHsm.route('/encrypt', methods=['GET', 'POST'])
def encrypt_route():
    if request.method == 'GET':
        return render_template('encryptMessage.html')
    # POST logic remains the same
    key_id = request.form.get('key_id') 
    data = request.form.get('data')
    if not key_id or not data:
        return jsonify({'error': 'Key ID and data are required'}), 400
    
    try:
        encryptedData = encrypt(data, key_id)
        return render_template('encryptMessage.html', encrypted_data=encryptedData)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        return jsonify({'error': f'Error: {str(e)}'}), 500
#######################################
    


######################################
@kmipHsm.route('/decrypt', methods=['GET', 'POST'])
def decrypt_route():
    # Extract inputs
    if request.method == 'GET':
        return render_template('decryptMessage.html')
    key_id = request.form.get('key_id')
    encrypted_data_b64 = request.form.get('encrypted_data')
    try:
        if not key_id or not encrypted_data_b64:
            return jsonify({'error': 'Key ID and encrypted data are required'}), 400
        
        decryptedData = decrypt(key_id, encrypted_data_b64)
        return render_template('decryptMessage.html', decrypted_data=decryptedData)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        return jsonify({'error': f'Error: {str(e)}'}), 500
######################################



######################################
@kmipHsm.route('/sign', methods=['GET', 'POST'])
def sign_route():
    if request.method == 'GET':
        return render_template('signVerify.html')
    key_id = request.form.get('key_id')
    message = request.form.get('message')
    if not key_id or not message:
        return jsonify({'error': 'Key name and message are required'}), 400
    
    try:
        signature = sign(key_id,message)
        return render_template('signVerify.html', signature=signature)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        #return jsonify({'error': f'Error: {str(e)}'}), 500
        return render_template('signVerify.html')
######################################    



######################################
@kmipHsm.route('/verify', methods=['GET', 'POST'])
def verify_route():
    if request.method == 'GET':
        return render_template('signVerify.html')
    key_id = request.form.get('key_id')
    message = request.form.get('message')
    signature_b64 = request.form.get('signature')

    if not key_id or not message or not signature_b64:
        return jsonify({'error': 'Key name, message, and signature are required'}), 400
    
    try:
        strResponse = verify(key_id, message, signature_b64)
        return render_template('signVerify.html', verification_result=strResponse)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        return jsonify({'error': f'Error: {str(e)}'}), 500
######################################


######################################
@kmipHsm.route('/destroy', methods=['GET', 'POST'])
def destroy_route():
    key_id = request.form.get('key_id')
    if request.method == 'GET':
        return render_template('destroyKey.html')
    try:
        strResponse = destroy(key_id)
        return render_template('destroyKey.html', message=strResponse)
    except Exception as e:
        error_message = traceback.format_exc()
        print(f"Error: {error_message}")
        return jsonify({'error': f'Error: {str(e)}'}), 500
######################################    









'''
#######################################
##KMIP ROUTE TO FUNCTIONS
#######################################
#These routes have been left in to recognize the attempt made to also have
#proper kmip endpoints, these enpoints expect a client_identity, which
#even if our endpoints were working did not plan on verifying due to time constraints

#That said we were prepared to have requests been either empty payloads or 
#EncryptedRequestPayloads of structure
#payload: {"unique_identifier": key_id, "data": [x,y]}
#data is an array for functions like verifying which requires the original message
#along with the signature

#######################################
def kmip_create_key(client_identity, request):
    """KMIP operation: Create a symmetric key."""
    try:
        key_id = create_symmetric_key()  # Call the core function
        return key_id
    except Exception as e:
        raise KmipOperationError(f"Failed to create key: {str(e)}")
#######################################    



#######################################
def kmip_create_key_pair(client_identity, request):
    """KMIP operation: Create an Asymmetric key."""
    try:
        key_id = create_Asymmetric_key()
        return key_id
    except Exception as e:
        raise KmipOperationError(f"Failed to create key: {str(e)}")
#######################################



######################################
def kmip_encrypt(clientID, request: EncryptRequestPayload) -> EncryptResponsePayload:
    
    try:
     
        
        key_id = request.unique_identifier
        data = request.data

        encryptedDataB64 = encrypt(key_id, data)
        encrypted_data_bytes = base64.b64decode(encryptedDataB64.encode('utf-8'))
        repPayload = EncryptResponsePayload(unique_identifier=key_id,data=encrypted_data_bytes)
        return repPayload
        
    except Exception as e:
        print(f"Error in KMIP encrypt: {e}")
        raise KmipOperationError(f"Failed to encrypt: {str(e)}")
######################################



######################################
def kmip_decrypt(client_identity, request: EncryptRequestPayload) -> EncryptResponsePayload:
    #not implementing clientID verification but is there for post due date impelmentation
    try:
        key_id = request.unique_identifier
        data = request.data

        decryptedDataB64 = decrypt(key_id, data)
        decrypted_data_bytes = base64.b64decode(decryptedDataB64.encode('utf-8'))
        repPayload = EncryptResponsePayload(unique_identifier=key_id,data=decrypted_data_bytes)
        return repPayload
    except Exception as e:
        print(f"Error in KMIP decrypt: {e}")
        raise KmipOperationError(f"Failed to decrypt: {str(e)}")
######################################



######################################    
def kmip_sign(client_identity, request:  EncryptRequestPayload) -> EncryptResponsePayload:
    #not implementing clientID verification but is there for post due date impelmentation
    try:
        key_id = request.unique_identifier
        data = request.data

        signatureB64 = sign(key_id, data)
        repPayload = EncryptResponsePayload(unique_identifier=key_id,data=signatureB64)
        return repPayload
    except Exception as e:
        print(f"Error in KMIP sign: {e}")
        raise KmipOperationError(f"Failed to sign: {str(e)}")
######################################

    

######################################
def kmip_verify(cleint_identity, request:  EncryptRequestPayload) -> EncryptResponsePayload:
    #not implementing clientID verification but is there for post due date impelmentation
    try:
        key_id = request.unique_identifier
        message = request.data[0]
        signature = request.data[1]
        stringResponse = verify(key_id, message, signature)

        repPayLoad = EncryptResponsePayload(unique_identifier=key_id,data=stringResponse)
        return repPayLoad
    except Exception as e:
        print(f"Error in KMIP verify: {e}")
        raise KmipOperationError(f"Failed to verify: sign {str(e)}")
######################################


  
        



'''

######################################
if __name__ == "__main__":
    init_db()
    # Flask server configuration

    kmipHsm.run(host="127.0.0.1", port=5000, debug=True)
 
    # KMIP server configuration (unfortunately this is blocked by the the .run process
    #trying to run both through threading had its own issues not accountinng for the issues
    #running the kmipServer on its own witht he inproper ssl.wrap_socket issues)

    #this could be resolved by downgrading our python install but the same would have to be
    #the case on the BBB, even if this was accomplished we had other errors with the kmips server
    #that needed to be addressed
    '''
    kmip_server = KmipServer(
        hostname="127.0.0.1",
        port=5696,  # Standard KMIP port
        certificate_path="certificate.pem",
        key_path="private_key.pem",
        ca_path="certificate.pem",
        database_path=DB_NAME,
        config_path="server.conf"
    )
    
    with kmip_server:
        kmip_server.serve()
    '''
######################################