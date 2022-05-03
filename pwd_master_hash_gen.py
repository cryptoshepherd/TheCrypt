from hashlib import sha256
import hashlib
import pwd_strenght_check
from Crypto.Random import get_random_bytes

def master_pwd_hash_gen():

    master_password = input("Enter your password: ")
    password = pwd_strenght_check.master_password_check(master_password)
    compile_factor_together = hashlib.sha256(password).hexdigest()
    
    salt = get_random_bytes(32)
    print('Please Copy the random bytes generated, you have to insert it into the pwd_naster.py')
    print(f'Salt: {salt}')
    print(f"Master Password: " + str(compile_factor_together))

master_pwd_hash_gen()
