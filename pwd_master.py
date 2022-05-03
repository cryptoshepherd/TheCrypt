from hashlib import sha256
import getpass
from base64 import b64encode, b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES



salt = b'\xb0^\xa2\x15\x9b]\xbb\x8ew\xcf\x94\xda\xbe%\x99\x83\x19\x8e`\xd3\x86DB\x06\x958;\xbd\x9df\xc7\x10'

def query_master_pwd(master_password, second_FA_location): 

    # Enter password hash in ******** field. Use PBKDF2 and Salt from above. Use master_password_hash_generator.py to generate a master password hash.
    master_password_hash = "b0f0e4efd400b3aa099b5c02b4009bcd4bca0de9a56a4c2f016a7da1f68820c6"

    compile_factor_together = sha256(master_password + second_FA_location).hexdigest()

    if compile_factor_together == master_password_hash: 
        return True


def encrypt_password(master_password_input, data):
    key = PBKDF2(master_password_input, salt, dkLen=32)
    data_bytes = bytes(data, 'utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data_bytes)
    add_nonce = ciphertext + nonce
    encoded_ciphertext = b64encode(add_nonce).decode()
    return print(encoded_ciphertext)



def decrypt_passowrd():
    master_password_input = getpass.getpass("Master Password: ")
    key = PBKDF2(master_password_input, salt, dkLen=32)
    if len(encoded_ciphertext) % 4:
        encoded_ciphertext += '=' * (4 - len(encoded_ciphertext) % 4)
    convert = b64decode(encoded_ciphertext)
    nonce = convert[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(convert[:-16])
    return plaintext