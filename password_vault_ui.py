from baseUI import BaseUI
from password_vault_database import password_vault
from tkinter import messagebox, ttk
import random
import string


class password_vault_ui(BaseUI):
    def __init__(self, master, app):
        super().__init__(master)
        # reference to the main app
        self.app = app

        # check for mouse and keyboard movement which reset the session timer
        self.master.bind("<Motion>", lambda _: self.app.reset_session_timer())
        self.master.bind("<Key>", lambda _: self.app.reset_session_timer())

        self.file_path = "images/password_vault/"
        # get user name from app
        self.current_user = self.app.current_user
        # get password from app
        self.current_password = self.app.current_password
        # initialise password vault with user details
        self.user_database = password_vault(self.current_user, self.current_password)
        # track entry being edited
        self.edit_index = None

        # images
        self.add_image(self.canvas, 724, 511, "background_img.png", self.file_path)
        self.add_image(self.canvas, 720, 112, "title_img.png", self.file_path)
        self.add_image(self.canvas, 720, 262, "password_vault_title_background.png", self.file_path)
        self.add_image(self.canvas, 150, 184, "navigation_background.png", self.file_path)
        self.add_image(self.canvas, 548, 662, "add_password_background.png", self.file_path)
        self.add_image(self.canvas, 1092, 662, "list_of_password_background.png", self.file_path)
        self.add_image(self.canvas, 149, 482, "user_account_background.png", self.file_path)
        self.add_image(self.canvas, 150, 450, "current_user_label_background.png", self.file_path)
        self.add_image(self.canvas, 548, 376, "add_password_headline.png", self.file_path)
        self.add_image(self.canvas, 1092, 376, "password_list_headline.png", self.file_path)
        self.add_image(self.canvas, 149, 723, "generate_password_background.png", self.file_path)
        self.add_image(self.canvas, 149, 633, "generate_password_text_background.png", self.file_path)

        # buttons
        self.add_button(41, 482, 213, 54, "Log out",
                        self.logout,
                        "#6949B4", "#D3495E")

        self.add_button(435, 732, 222, 59, "Add",
                        self.save_entries,
                        "#B170A0", "#D2495F")

        self.add_button(45, 704, 213, 84, "Generate \nPassword",
                        self.generate_password,
                        "#6949B4","#FF9898")

        self.add_button(18, 148, 267, 96, "Encrypt",
                        self.app.encrypt_ui,
                        "#6949B4", "#D9D9D9")

        self.add_button(15, 253, 270, 103, "Decrypt",
                        self.app.decrypt_ui,
                        "#6949B4", "#D9D9D9")

        self.add_button(15, 43, 270, 97, "FAQ/Help",
                        self.app.faq_ui,
                        "#6949B4", "#D9D9D9")

        # user entry
        self.entry_name = self.entry(374, 490, 348, 53, "Name", "#AD72CC", None)
        self.entry_username = self.entry(372, 572, 348, 53, "User name", "#AE71BD", None)
        self.entry_password = self.entry(374, 654, 348, 53, "Password", "#AF71AF", None)

        # title
        self.canvas.create_text(
            470, 200, anchor="nw",
            text="Password Vault",
            fill="#FFFFFF",
            font=("Khula Bold", 70)
        )

        # user currently logged in username
        self.canvas.create_text(
            90, 433, anchor="nw",
            text=self.current_user,
            fill="#FFFFFF",
            font=("Khula Bold", 24)
        )

        # display saved password entries
        self.display = ttk.Treeview(
            self.master,
            columns=("Name", "Username", "Password"),
            show="headings",
            selectmode="browse",
        )

        # treeview headings
        self.display.heading("Name", text="Name")
        self.display.heading("Username", text="Username")
        self.display.heading("Password", text="Password")
        self.display.place(x=856, y=410, width=472, height=500)

        # buttons for treeview

        self.add_button(860, 920, 222, 59, "Edit", self.edit, "#B46F7E", "#D2495F")
        self.add_button(1100, 920, 222, 59, "Delete", self.delete, "#B46F7E", "#D2495F")

        self.show_display()

    # password entry display
    def show_display(self):
        # clear existing entries
        for i in self.display.get_children():
            self.display.delete(i)

        # load and display entries from database
        database_data = self.user_database.get_details()

        for index, entry in enumerate(database_data):
            self.display.insert(
                "", "end", iid=index,
                values=(entry["name"], entry["username"], entry["password"])
            )

    # edit saved entries
    def edit(self):
        selection = self.display.selection()

        if not selection:
            messagebox.showerror("error", "Please Select to edit")
            return

        entry_index = int(selection[0])
        entry = self.user_database.get_details()[entry_index]

        # populate entry fields with selected data
        self.entry_name.delete(0, "end")
        self.entry_name.insert(0, entry["name"])

        self.entry_username.delete(0, "end")
        self.entry_username.insert(0, entry["username"])

        self.entry_password.delete(0, "end")
        self.entry_password.insert(0, entry["password"])

        # track index for update
        self.edit_index = entry_index

    #delete selected password entry
    def delete(self):
        selection = self.display.selection()
        if not selection:
            messagebox.showerror("error", "please select to delete")
            return

        confirmation = messagebox.askyesno("Confirm Deletion", "Do you want to delete it?")

        if not confirmation:
            return

        entry_index = int(selection[0])
        self.user_database.delete_details(entry_index)

        # refresh display
        self.show_display()

    # save new or update password entry
    def save_entries(self):
        name = self.entry_name.get()
        username = self.entry_username.get()
        password = self.entry_password.get()

        if not name or not username or not password:
            messagebox.showerror("error", "please all the details")

        if self.edit_index is not None:
            # update existing entry
            self.user_database.update_details(
                self.edit_index, name, username, password
            )
            self.edit_index = None  # reset edit mode

        else:
            self.user_database.add_details(name, username, password)

        # clear entries and refresh display
        self.show_display()
        self.entry_name.delete(0, "end")
        self.entry_username.delete(0, "end")
        self.entry_password.delete(0, "end")

    # generate random strong password
    def generate_password(self):
        letters = string.ascii_letters + string.digits + string.punctuation
        length = [8, 10, 12, 14]
        password = ''.join(random.choice(letters) for _ in range(random.choice(length)))  # for a 20-character password

        # display generated password in password entry and other place
        text = self.text(33, 609, "#8058DF", "#6949B4", 232, 54)
        text.delete("1.0", "end")
        text.insert("end", password)

        self.entry_password.delete(0, "end")
        self.entry_password.insert("end", password)

    # log out
    def logout(self):
        self.app.logout_all()

    # start session
    def start_session(self):
        self.app.reset_session_timer()  # Use app-level timer
        self.app.logged_in = True
        self.app.password_vault_ui()
