import json
import traceback
import base64
from os import listdir, remove, system, name
from tkinter import *
import string
import random
from shutil import copyfile
from getpass import getpass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

PASSWORDS_FILE = "password.encrypted"
PASSWORDS_FILE_BACKUP = "password.encrypted.backup"


def tk_multiline_input( initial_text = "" ):
    tk_multiline_input.tkpassword = initial_text # this name so it can be accessed in _save function
    
    window = Tk()
    window.title("enter the password to save")
    window.geometry("500x330")

    textbox = Text(window, width = 100, height = 15)
    textbox.pack()

    # if password already saved fill input
    if tk_multiline_input.tkpassword:
        textbox.insert(1.0, tk_multiline_input.tkpassword)

    def _generate_random_passw():
        characters = string.ascii_letters + string.punctuation + string.digits
        password = "".join(random.choice(characters) for x in range(random.randint(15, 20)))
        textbox.insert(END, f"password: {password}\n")
    Button(window, text = "generate random", command = _generate_random_passw).pack()

    def _save():
        tk_multiline_input.tkpassword = textbox.get(1.0, END)
        window.destroy()
    Button(window, text = "submit", command = _save).pack()

    window.mainloop()
    return tk_multiline_input.tkpassword.removesuffix("\n")


class PasswordManager():
    def __init__(self, password):
        self.key = self._get_key(password)

        # create file if not existent
        if PASSWORDS_FILE not in listdir():
            self.save_passwords({}) # add empty dict to set the password inputed first as key
            print("created passwords file")

    def _get_key(self, password: str) -> bytes:
        # print(os.urandom(16))
        salt = b"\xde\xd1\xcc\xec\xdem'\x05\xfd\x9d\x8de\\\xec\x03\xc5"

        kdf = PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 32,
            salt = salt,
            iterations = 100000,
            backend = default_backend()
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode())) # can only use kdf once
        
        return key
    
    def set_key(self):
        self.key = self._get_key(getpass("re-insert password to generate the decryption key >>> "))

    

    def decrypt_message(self, encrypted: bytes):
        f = Fernet(self.key)

        decrypted = f.decrypt(encrypted)
        return decrypted.decode()
    
    def encrypt(self, new_passwords_dict: dict):
        # encode message
        encoded = json.dumps(new_passwords_dict).encode()

        #encrypt message
        f = Fernet(self.key)
        encrypted = f.encrypt(encoded)

        return encrypted
    

    def load_passwords(self):
            
        with open(PASSWORDS_FILE, "rb") as encryptedfile:
            DATA = encryptedfile.read()
        
        decrypted = self.decrypt_message(DATA)
        return json.loads(decrypted)

    def save_passwords(self, passwords: dict):
        with open(PASSWORDS_FILE, "wb") as encryptedfile:
            encryptedfile.write(self.encrypt(passwords))
    
    def create_backup(self):
        with open(PASSWORDS_FILE_BACKUP, "wb") as encryptedfile:
            encryptedfile.write(self.encrypt(self.load_passwords()))
            
        print(f"backupped data to '{PASSWORDS_FILE_BACKUP}'")
    
    def load_backup(self):
        if input("confirm choice? y/n >>> ").lower() != "y":
            print("process cancelled")
            return

        if PASSWORDS_FILE_BACKUP not in listdir():
            print("backup file not found")
            return
        
        if PASSWORDS_FILE in listdir():
            remove(PASSWORDS_FILE)
        
        copyfile(PASSWORDS_FILE_BACKUP, PASSWORDS_FILE)
        print("replaced data with backup")
        


    def add_new_password(self):
        # add to end of passwords -> {app: password} if app not in passwords
        
        passwords = self.load_passwords()

        app = input("insert name of the new app >>> ")
        if app in passwords.keys():
            print(f"password of '{app}' already saved")
            return

        print("insert password on popup window")
        password = tk_multiline_input()
        passwords[app] = password

        self.save_passwords(passwords)
    
    def modify_password(self):
        # give choice to append at the end or replace all content
        passwords = self.load_passwords()

        app = input("insert name of the app to modify >>> ")
        if app not in passwords.keys():
            print(f"password of '{app}' not found")
            return

        password = tk_multiline_input(initial_text = passwords[app])
        passwords[app] = password

        self.save_passwords(passwords)
        
    def remove_password(self):
        passwords = self.load_passwords()

        app = input("insert name of the app to remove >>> ")
        if app not in passwords.keys():
            print(f"password of '{app}' not found")
            return

        if input(f"confirm the removation of '{app}'? y/n >>> ").lower() in ["y", "yes"]:
            del passwords[app]
            print("app removed")

            self.save_passwords(passwords)
        else: print("process cancelled")
    
    # print data
    def print_available_apps(self):
        print("".join([ f"{n} - {app}\n" for n, app in enumerate(self.load_passwords().keys()) ]))
    
    def get_app_password(self):
        print(self.load_passwords().get(input("search for an app >>> "), "app not found"))
    
    def create_unencrypted_file(self):
        with open("unencrypted.json", "w") as unencryptedfile:
            json.dump(self.load_passwords(), unencryptedfile, indent = 4)
        print("created file 'unencrypted.json'")
    
    def load_from_json(self):
        print("to be sure create a backup")
        with open(input("json file path >> "), "r") as jsonfile:
            self.save_passwords(json.load(jsonfile))

        print("replaced passwords file correctly.")


# START PROGRAM
#TODO fix input -> replace with getpass, getpass does not support non unicode charfacters
# in video of neuralnine try using second method

pm = PasswordManager(input("insert password to generate the decryption key >>> "))

actions = {
    "get all available apps": pm.print_available_apps,
    "visualize a app's password": pm.get_app_password,
    "add a new password": pm.add_new_password,
    "modify a password": pm.modify_password,
    "remove a password": pm.remove_password,
    "create a backup": pm.create_backup,
    "replace password data with backup": pm.load_backup,
    "create unencrypted file": pm.create_unencrypted_file,
    "replace password data with json file data": pm.load_from_json,
    "re-insert password to generate the decryption key": pm.set_key,
    "quit": exit
}

while True:
    try:
        # clear screen
        system("cls" if name == "nt" else "clear")

        # print actions
        print("\n".join([ f"{n + 1}) {action}" for n, action in enumerate(actions.keys())]))

        choice = input(">>> ")
        if not choice:
            continue

        elif not choice.isdecimal():
            print("please enter a number")

        elif not 0 <= int(choice) <= len(actions.keys()):
            print("not a suitable option")

        else:
            actions[list(actions.keys())[int(choice) - 1]]() # call function from actions dict
                
        input("\npress enter to continue...")
    
    except Exception:
        print("\n----- encountered an error -----")
        traceback.print_exc()
        input("-"*32)
