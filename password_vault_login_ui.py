from baseUI import BaseUI
from user_database import user_account
from tkinter import messagebox


def check_password(password):
    # 8 characters long
    if len(password) < 8:
        return "Password must be at least 8 characters long"
    # uppercase
    if not any(p.isupper() for p in password):
        return "Password must contain at least one uppercase letter"
    # lowercase
    if not any(p.islower() for p in password):
        return "Password must contain at least one lowercase letter"
    # number
    if not any(p.isdigit() for p in password):
        return "Password must contain at least one number"
    # special character
    if not any(p in '!@#$%^&*()_+-=[]{};:,.<>?/' for p in password):
        return "Password must contain at least one special character"
    return None


class password_vault_login_ui(BaseUI):
    def __init__(self, master, app):
        super().__init__(master)
        self.app = app

        # # reset session timer if mouse is moved or key is pressed or moved
        self.master.bind("<Motion>", lambda _: self.app.reset_session_timer())
        self.master.bind("<Key>", lambda _: self.app.reset_session_timer())

        # if user already logged in
        if self.app.logged_in:
            self.app.password_vault_ui()
            return

        # file path for the images
        self.file_path = "images/passwordVault_login/"


        # Images
        self.add_image(self.canvas, 724, 511, "background_img.png", self.file_path)
        self.add_image(self.canvas, 720, 112, "title_img.png", self.file_path)
        self.add_image(self.canvas, 720, 262, "password_vault_title_background.png", self.file_path)
        self.add_image(self.canvas, 150, 184, "navigation_background.png", self.file_path)
        self.add_image(self.canvas, 461, 702, "create_account_background.png", self.file_path)
        self.add_image(self.canvas, 980, 702, "login_background.png", self.file_path)
        self.add_image(self.canvas, 459, 500, "create_account_title.png", self.file_path)
        self.add_image(self.canvas, 984, 500, "login_text.png", self.file_path)

        # heading text
        self.canvas.create_text(
            475, 200,
            anchor="nw",
            text="Password Vault",
            fill="#FFFFFF",
            font=("Khula Bold", 70)
        )

        # Buttons
        self.add_button(292, 833, 338, 68,
                        "Create Account",
                        self.create_account,
                        "#A463A2", "#b84f4f")   # Create Account Button

        self.add_button(811, 759, 343, 72,
                        "Login",
                        self.login,
                        "#A463A2", "#b84f4f")   # Login Button

        self.add_button(20, 46, 261, 87,
                        "Encrypt",
                        self.app.encrypt_ui,
                        "#6949B4", "#D9D9D9")   # Encrypt UI Navigation

        self.add_button(20, 151, 261, 86,
                        "Decrypt",
                        self.app.decrypt_ui,
                        "#6949B4", "#D9D9D9")   # Decrypt UI Navigation

        self.add_button(20, 258, 261, 87,
                        "Help/FAQ",
                        self.app.faq_ui,
                        "#6949B4", "#D9D9D9")   # FAQ UI Navigation

        # Entries
        self.create_username = self.entry(319, 592, 281, 58, "User Name", "#A263AA", None)
        self.create_password = self.entry(319, 675, 281, 58, "Enter Password", "#A463A0", "*")
        self.create_confirm_password = self.entry(319, 756, 281, 58, "Confirm Password", "#A66499", "*")

        self.login_username = self.entry(843, 588, 281, 58, "User Name", "#A163AD", None)
        self.login_password = self.entry(843, 685, 281, 58, "Password", "#A363A4", "*")

    # user login function
    def login(self):
        # get the username and password from entries
        # username will not have any spaces and will be lowercase
        username = self.login_username.get().lower().strip()
        password = self.login_password.get()

        # if user does not enter username or password
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return

        # opens the database
        database = user_account()

        # Username exists or no
        if not database.user_exists(username):
            messagebox.showerror("Error", "Username does not exist")
            return

        # verify user
        if database.verify_user(username, password):
            self.app.current_user = username
            self.app.current_password = password
            self.app.reset_session_timer()  # Start session timer
            self.app.logged_in = True  # set logged in to true
            database.reset_attempts(username)
            self.app.password_vault_ui()  # open password vault ui

            messagebox.showinfo("Success", "Logged in successfully")
        else:
            # if the user is locked
            if database.check_account_locked(username):
                message = "Account locked - try again later"
            else:
                # show user remaining attempts
                remaining = database.remaining_attempts(username)
                message = "Username and password do not match" + str(remaining) + " attempts remaining"
            messagebox.showerror("Error", message)



    def create_account(self):
        # get username and passwords from entries
        # username will not have any spaces and will be lowercase

        username = self.create_username.get().strip().lower()
        password = self.create_password.get()
        confirm_password = self.create_confirm_password.get()

        # if user does not enter username
        if not username:
            messagebox.showerror("Error", "Username cannot be empty")
            return
        # if user enters special characters in username
        if any(u in username for u in '!@#$%^&*()'):
            messagebox.showerror("Error", "Username can not contain special characters")
            return

        # Check if passwords match
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            return

        # validate strong password
        error_message = check_password(password)
        if error_message:
            messagebox.showerror("Error", error_message)
            return

        # Create the account
        database = user_account()

        # return true if account is created successfully
        if database.create_account(username, password):
            messagebox.showinfo("Success", "Account created successfully")

            # clear the entries
            self.create_username.delete(0, 'end')
            self.create_password.delete(0, 'end')
            self.create_confirm_password.delete(0, 'end')
        else:
            messagebox.showerror("Error", "Username already exists")



