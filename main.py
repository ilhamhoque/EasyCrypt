import threading
import sys
import customtkinter as ctk
from faq_ui import faq_ui
from homepageUI import homepageUI
from EncryptUI import EncryptUI
from DecryptUI import DecryptUI
from password_vault_ui import password_vault_ui
from password_vault_login_ui import password_vault_login_ui

from tkinter import messagebox

class App:
    def __init__(self):
        # Main Window settings
        self.window = ctk.CTk()
        # window size
        self.window.geometry("1440x1024")
        # window title
        self.window.title("EasyCrypt")
        # track current frame
        self.current_frame = None
        # initialise with homepage
        self.homepage_ui()
        # disable window resize
        self.window.resizable(False, False)

        # track if user logged in or not
        self.logged_in = False
        # timer for session expire
        self.session_timer = None
        # 5 minutes in seconds
        self.session_duration = 300
        # prevents multiple logout calls
        self.logout_pending = False
        # stores current user name
        self.current_user = None
        # stores the current password
        self.current_password = None

        # handle window close event
        self.window.protocol("WM_DELETE_WINDOW", self.close_app)

    # Clear Current Frame
    def clear_current_frame(self):
        # destroy all widgets in the current frame
        if self.current_frame:
            # Cancel session timer when leaving vault UI
            if hasattr(self.current_frame, 'session_timer'):
                if self.current_frame.session_timer:
                    self.current_frame.session_timer.cancel()
            # remove all existing widgets from the window
            for widget in self.window.winfo_children():
                widget.destroy()

    # Homepage Interface
    def homepage_ui(self):
        self.clear_current_frame()
        self.current_frame = homepageUI(self.window, self)

    # # Encryption Interface
    def encrypt_ui(self):
        self.clear_current_frame()
        self.current_frame = EncryptUI(self.window, self)
    #
    # # Decryption interface
    def decrypt_ui(self):
        self.clear_current_frame()
        self.current_frame = DecryptUI(self.window, self)
    #
    # # Password Vault Interface
    def password_vault_ui(self):
        self.clear_current_frame()
        self.current_frame = password_vault_ui(self.window, self)
    #
    # # password login page
    def password_vault_login_ui(self):
        if self.logged_in:
            # skips login ui if already logged in
            self.password_vault_ui()
            return
        self.clear_current_frame()
        self.current_frame = password_vault_login_ui(self.window, self)
    #
    # reset session timer
    def reset_session_timer(self):
        if self.session_timer:
            # cancel existing timer
            self.session_timer.cancel()
        # create new daemon timer so it does not block app exit
        self.session_timer = threading.Timer(self.session_duration, self.logout_all)
        self.session_timer.daemon = True
        self.session_timer.start()
    #
    # # log out
    def logout_all(self):
        if not self.logged_in and not self.logout_pending:
            return

        self.logout_pending = True
        self.logged_in = False

        if self.session_timer:
            self.session_timer.cancel()
            self.session_timer = None

        # Only show message if not already on homepage
        if not isinstance(self.current_frame, homepageUI):
            messagebox.showinfo("Session Ended", "Automatic logout due to inactivity")

        self.homepage_ui()
        self.logout_pending = False
    #
    # # FAQ page
    def faq_ui(self):
        self.clear_current_frame()
        self.current_frame = faq_ui(self.window, self)

    # close app
    def close_app(self):
        if self.session_timer:
            # stop running timers
            self.session_timer.cancel()
        # close main window
        self.window.destroy()
        # exit application
        sys.exit()

    # Application start
    def run(self):
        self.window.mainloop()


if __name__ == "__main__":
    app = App()
    app.run()
