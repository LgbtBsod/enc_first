from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Encrypts the gi v e n message with the gi v e n p u bli c key
def rsa_encrypt ( enc_keys , public_key ) :
    encrypted_keys = public_key . encrypt (
    enc_keys ,
    padding .OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()) ,
    algorithm=hashes.SHA256(),
    label=None
    ))
    return encrypted_keys
# Dec ryp t s the gi v e n c i p h e r t e x t with the gi v e n p r i v a t e key
def rsa_decrypt ( encrypted_keys , private_key ) :
    decrypted_keys = private_key.decrypt (
    encrypted_keys,
    padding .OAEP(
    mgf=padding .MGF1(algorithm=hashes.SHA256()) ,
    algorithm=hashes.SHA256() ,
    label=None))
    return decrypted_keys
# Gene ra te s a new p r i v a t e key
def generate_private_key() :

    private_key = rsa.generate_private_key (
    public_exponent =65537 ,
    key_size =2048,
    backend=default_backend()
    )
    return private_key
# Returns the p u bli c key f o r the gi v e n p r i v a t e key
def get_public_key (private_key ) :
    public_key = private_key.public_key ( )
    return public_key