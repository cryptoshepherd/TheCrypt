from hashlib import sha256
import getpass
from base64 import b64encode, b64decode
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

# Here your generated Salt
salt = b''


def query_master_pwd(master_password, second_FA_location):
    # Enter password hash in ******** field. Use PBKDF2 and Salt from above. Use master_password_hash_generator.py to
    # generate a master password hash.
    master_password_hash = ""

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
    return encoded_ciphertext


def decrypt_password(master_password_input, encoded_ciphertext):
    key = PBKDF2(master_password_input, salt, dkLen=32)
    if len(encoded_ciphertext) % 4:
        encoded_ciphertext += '=' * (4 - len(encoded_ciphertext) % 4)
    convert = b64decode(encoded_ciphertext)
    nonce = convert[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(convert[:-16])
    return plaintext
