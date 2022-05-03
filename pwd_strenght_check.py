import string
from tkinter import messagebox, simpledialog
from unittest import skip
import pwd_master


# Check Password strenght and check password against a commons passowrd dict
def password_check(master_password):
    password = master_password
    # upper = ([1 if c in string.ascii_uppercase else 0 for c in master_pwd]) This returns a list of 0 1
    # upper = any([1 if c in string.ascii_uppercase else 0 for c in master_pwd]) This returns True or False
    upper_case = any([1 if _ in string.ascii_uppercase else 0 for _ in password])
    lower_case = any([1 if _ in string.ascii_lowercase else 0 for _ in password])
    digits = any([1 if _ in string.digits else 0 for _ in password])
    special_case = any([1 if _ in string.punctuation else 0 for _ in password])

    
    characters = [upper_case, lower_case, digits, special_case]
    #print(characters)
    length = len(password)
    score = 0

    with open('common.txt', 'r') as f:
        common = f.read().splitlines()
    if password in common:
        messagebox.showerror('Error', f"Password is {length} length, and was found in a common list. The password score is 7 / 0")
        # print(f"Password is {length} length, and was found in a common list. The password score is 7 / 0")
    
    if length > 8:
        score += 1
    if length > 12:
        score += 1
    if length > 18:
        score += 1
    if length > 21:
        score += 1
    # print(f"Password length is {str(length)}, adding {str(score)} points")


    if sum(characters) > 1:
        score += 1
    if sum(characters) > 2:
        score += 1
    if sum(characters) > 3:
        score += 1
    # print(f"password has {str(sum(characters))} character type, adding {str(sum(characters) -1)} points")

    if password not in common and score < 4:
        # print(f'The password is too weak! Score:{str(score)} / 7')
        messagebox.showerror('Error', f'The password is too weak! Score:{str(score)} / 7')
    elif score == 4:
        # print(f"The password is OK! Score:{str(score)} / 7")
        res = messagebox.askyesno('Aknowledge', f"The password is OK! Score:{str(score)} / 7. Are you OK?")
        if res == True:
            return password
        elif res == False:
            pass
    elif score > 4 and score < 6:
        # print(f"The password is pretty strong! Score:{str(score)} / 7")
        res = messagebox.askyesno('Aknowledge', f"The password is pretty strong! Score:{str(score)} / 7. Are you OK?")
        if res == True:
            return password
        elif res == False:
            pass
    elif score > 6:
        # print(f"The password is strong! Score:{str(score)} / 7")
        res = messagebox.askyesno('Aknowledge', f"The password is strong! Score:{str(score)} / 7. Are you OK?")
        if res == True:
            return password
        elif res == False:
            pass


# Check the master password for strenght and against a commons password dict
def master_password_check(master_password):
    password = master_password
    # upper = ([1 if c in string.ascii_uppercase else 0 for c in master_pwd]) This returns a list of 0 1
    # upper = any([1 if c in string.ascii_uppercase else 0 for c in master_pwd]) This returns True or False
    upper_case = any([1 if _ in string.ascii_uppercase else 0 for _ in password])
    lower_case = any([1 if _ in string.ascii_lowercase else 0 for _ in password])
    digits = any([1 if _ in string.digits else 0 for _ in password])
    special_case = any([1 if _ in string.punctuation else 0 for _ in password])

    
    characters = [upper_case, lower_case, digits, special_case]
    # Sprint(characters)
    length = len(password)
    score = 0

    with open('common.txt', 'r') as f:
        common = f.read().splitlines()
    if password in common:
        print(f"Password is {length} length, and was found in a common list. The password score is 7 / 0")
    
    if length > 8:
        score += 1
    if length > 12:
        score += 1
    if length > 18:
        score += 1
    if length > 21:
        score += 1
    # print(f"Password length is {str(length)}, adding {str(score)} points")


    if sum(characters) > 1:
        score += 1
    if sum(characters) > 2:
        score += 1
    if sum(characters) > 3:
        score += 1
    # print(f"password has {str(sum(characters))} character type, adding {str(sum(characters) -1)} points")

    if password not in common and score < 4:
        print(f'The password is too weak! Score:{str(score)} / 7')
    elif score == 4:
        print(f"The password is OK! Score:{str(score)} / 7")
        return password
    elif score > 4 and score < 6:
        print(f"The password is pretty strong! Score:{str(score)} / 7")
        return password
    elif score > 6:
        print(f"The password is strong! Score:{str(score)} / 7")
        return password

