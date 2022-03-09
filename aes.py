import os
import hmac
import hashlib
from rsa_enc import get_public_key,generate_private_key,rsa_encrypt, rsa_decrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat. primitives.ciphers import Cipher , algorithms , modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat. backends import default_backend

backend = default_backend ()
aes_key = os . urandom (32 )
iv = os.urandom (16 )
hmac_key = os.urandom (32 )

def start_crypt():
    private_key = generate_private_key()
    public_key = get_public_key (private_key )
    return public_key , private_key
#e n c r y p t
def encryption ( public_key , message ) :
    padder = padding .PKCS7(128 ).padder ( )
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv) , backend=backend)
    encryptor = cipher.encryptor()
    
    padded_message = padder.update ( message.encode()) + padder.finalize()
    ciphertext = encryptor.update (padded_message) + encryptor.finalize()
    
    
    tag = hmac.new(hmac_key, ciphertext, digestmod=hashlib.sha256).digest()
    keys = aes_key + hmac_key +iv
    # g e t the c i p h e r t e x t from the b uff e r r ea di ng onl y the b y t e s w ri t t e n tkey s = aes_key + hmac_key + i v
    encrypted_keys = rsa_encrypt (keys, public_key)

    data = {'encrypted_keys':encrypted_keys.decode(encoding='latin1'),'ciphertext':ciphertext.decode(encoding='latin1'),'tag':tag.decode(encoding='latin1')}
    return data

#d e c r y p t

def decryption( data , private_key ) :
    ciphertext = bytes(data['ciphertext'], encoding='latin1')
    encrypted_keys = bytes(data['encrypted_keys'] , encoding='latin1')
    tag = bytes(data['tag'], encoding='latin1')

    # RSA d e c r y p ti ng the key s
    decrypt_keys = rsa_decrypt(encrypted_keys,private_key )
    # s e p a r a ti n g the AES and HMAC key s and IV back out
    aes_key = decrypt_keys[0:32]
    hmac_key = decrypt_keys[32:32+32]
    iv = decrypt_keys[32+32:32+32+16]
    
    tag_check = hmac.new(hmac_key , ciphertext , digestmod=hashlib.sha256).digest()

    if hmac.compare_digest(tag,tag_check) :
    # d e c r y p ti ng the c i p h e r t e x t
        cipher = Cipher (algorithms.AES(aes_key), modes.CBC(iv), backend=backend) 
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext)+decryptor.finalize()
        # unpadding the p l a i n t e x t
        unpadder = padding.PKCS7 (128).unpadder()
        plaintext = unpadder.update (padded_plaintext )+unpadder.finalize()
        plaintext = plaintext.decode()
        return  plaintext
    else:
        print("ERROR" )