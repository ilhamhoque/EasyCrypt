import os
import json
from tempfile import NamedTemporaryFile  # for safe file operation
from Encrypt_Decrypt import aes
import base64


class password_vault:
    def __init__(self, username, password):

        self.username = username
        # convert password to bytes
        self.password = password.encode("utf-8")
        self.salt = self.get_user_salt()    # get user salt

        if not self.salt:
            raise ValueError("salt not found")

        # get encryption key using PBKDF2
        # 48 byte key for AES 256
        self.enc_key = aes.password_encode(self.password,self.salt, 48)

        # create encrypted database filename
        self.database = "password_vault_" + str(username) + "_.json"
        # create empty password entries
        self.data = {"entries": []}

        # create AES cipher instance
        self.aes = aes(self.enc_key, aes_mode=256)

        # load existing data if database exists
        if os.path.exists(self.database):
            with open(self.database, 'rb') as f:
                enc_data = f.read()
                # decrypt json data
                dec_data = self.aes.decrypt(enc_data, b"")
                self.data = json.loads(dec_data.decode("utf-8"))

    # get users salt from user database
    def get_user_salt(self):
        user_database = "user_accounts.json"
        if not os.path.exists(user_database):
            raise FileNotFoundError("User database file cannot be found")

        with open(user_database, "r") as db:
            user_data = json.load(db)

        # extract and decode base64 salt from user data
        if self.username in user_data["users"]:
            salt = base64.b64decode(user_data["users"][self.username]["salt"])
            return salt
        else:
            raise ValueError ("salt not found for "+self.username)

    # encrypt and save the data into database
    def save(self):
        json_data = json.dumps(self.data, indent=2).encode("utf-8")
        # encrypt with AES
        enc_data = self.aes.encrypt(json_data, self.salt)

        # use temporary file for safe writing
        with NamedTemporaryFile(mode='wb', delete=False,
                                dir=os.path.dirname(self.database)) as temp:
            temp.write(enc_data)
            temp = temp.name

        # atomic replacement of database file
        os.replace(temp, self.database)

    # add user entry by index
    def add_details(self, name, username, password):
        self.data["entries"].append({
            "name": name,
            "username": username,
            "password": password,
        })
        self.save()

    # delete users data by index
    def delete_details(self, index):
        if 0 <= index < len(self.data["entries"]):
            self.data["entries"].pop(index)
            self.save()

    # modify user details
    def update_details(self, index, name, username, password):
        if 0 <= index < len(self.data["entries"]):
            self.data["entries"][index] = {
                "name": name,
                "username": username,
                "password": password,
            }

            self.save()

    # get all the details
    def get_details(self):
        return self.data["entries"]


