import os
import json
import hmac
import base64

import time
from tempfile import NamedTemporaryFile
from Encrypt_Decrypt import aes


class user_account:
    # max attempt before user gets locked
    max_attempt = 5
    # 5 minute in seconds
    time_locked = 300
    # database for storing user details
    database = 'user_accounts.json'

    def __init__(self):
        # data structure for user records
        self.data = {"users": {}}
        # load existing data if database exists
        if os.path.exists(self.database):
            with open(self.database, 'r') as d:
                self.data = json.load(d)

    # save user data with temporary file
    def save(self):
        with NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(self.database)) as temp:
            json.dump(self.data, temp, indent=2)
            temp_path = temp.name

        os.replace(temp_path, self.database)

    # create new user account with password
    def create_account(self, username, password):
        username = username.strip().lower()

        if self.user_exists(username):
            # if user name already exists in the database
            return False

        salt = os.urandom(16)
        # encrypt password with salt + 256 key
        password_encode = aes.password_encode(password, salt, 48)

        # store users record
        self.data["users"][username] = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "password_encode": base64.b64encode(password_encode).decode('utf-8'),
            "failed_attempts": 0,
            "last_attempts": None
        }
        self.save()
        return True

    # verify users details
    def verify_user(self, username, password):
        user = self.data["users"].get(username.strip().lower())
        if not user:
            # user not found
            return False

        # extract security parameters
        salt = base64.b64decode(user["salt"])
        stored_password_hash = base64.b64decode(user["password_encode"])
        attempts = user["failed_attempts"]
        last_attempts = user["last_attempts"]

        # check if the account is locked
        if self.user_locked(attempts, last_attempts):
            return False

        # validate failed attempts on failure
        if self.valid_password(password, salt, stored_password_hash):
            self.reset_attempts(username)
            return True

        # update failed attempts on failure
        self.save_failed_attempts(username)
        return False

    # secure password validation using HMAC
    def valid_password(self, password, salt, stored_password_hash):
        return hmac.compare_digest(stored_password_hash,
                                   aes.password_encode(password, salt, 48))

    # if account is locked based on attempts and timing
    def user_locked(self, attempts, last_attempts):
        return attempts >= self.max_attempt and \
               (time.time() - (last_attempts or 0)) < self.time_locked

    # reset failed attempts after successful login
    def reset_attempts(self, username):
        self.data["users"][username]["failed_attempts"] = 0
        self.data["users"][username]["last_attempts"] = time.time()
        self.save()

    # track failed login attempts
    def save_failed_attempts(self, username):
        self.data["users"][username]["failed_attempts"] += 1
        self.data["users"][username]["last_attempts"] = time.time()
        self.save()

    # check if user exists in the database
    def user_exists(self, username):
        return username.strip().lower() in \
               self.data["users"]

    # check if account is currently locked
    def check_account_locked(self, username):
        user = self.data["users"].get(username.strip().lower())
        if not user:
            return False
        return self.user_locked(user["failed_attempts"], user["last_attempts"])

    # get remaining allowed attempts before lockout
    def remaining_attempts(self, username):
        user = self.data["users"].get(username.strip().lower())
        if not user:
            return self.max_attempt
        return self.max_attempt - user["failed_attempts"]
