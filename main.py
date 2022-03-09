from aes import start_crypt, encryption, decryption


public_a , private_a = start_crypt()
public_b , private_b = start_crypt()
public_a , public_b = public_b , public_a

while True:
    message = input(':' )
    cipher_b = encryption(public_a , message )
    plaintext_b = decryption( cipher_b , private_b )
    message = input (':')
    cipher_a = encryption ( public_b , message )
    plaintext_a = decryption( cipher_a , private_a )
    print('Alice says', plaintext_b )
    print( 'Bob says ', plaintext_a )
    break
