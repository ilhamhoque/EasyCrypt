import multiprocessing
import os
from baseUI import BaseUI
from tkinter import messagebox, IntVar
import zipfile
import shutil
import hmac
import hashlib

import queue
from Encrypt_Decrypt import aes


# file compression and create ZIP
def file_compression(file_list, progress_queue):
    # if file_list is empty
    if not file_list:
        return None

    # use the first files directory and name for the archive
    archive_dir = os.path.dirname(file_list[0])
    base_name = os.path.splitext(os.path.basename(file_list[0]))[0]
    archive_path = os.path.join(archive_dir, base_name + ".zip")

    try:
        # create ZIP archive
        with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:
            for file_path in file_list:
                # use the files name in the archive
                arcname = os.path.basename(file_path)
                zipf.write(file_path, arcname=arcname)
                # delete the original file after adding to the archive
                os.remove(file_path)
    except Exception as error:
        progress_queue.put(("ERROR", str(error)))
        return None
    # returns the path to the created archive
    return archive_path


# folder compression and archive
def folder_compression(folder_path, progress_queue):
    # get the directory of the folder
    archive_dir = os.path.dirname(folder_path)
    # get the folder name
    folder_name = os.path.basename(folder_path)

    # create the archive path
    archive_path = os.path.join(archive_dir, folder_name + ".zip")
    try:
        # create a ZIP archive of the folder
        with zipfile.ZipFile(archive_path, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:

            for root, dirs, files in os.walk(folder_path):
                # walk through the folder
                for file in files:
                    full_path = os.path.join(root, file)
                    # Relative path in the archive
                    arcname = os.path.relpath(full_path, start=folder_path)
                    # Add the file to the archive
                    zipf.write(full_path, arcname=arcname)

        # Delete the original folder after archiving
        shutil.rmtree(folder_path)
    except Exception as error:
        progress_queue.put(("ERROR", str(error)))
        return None
    return archive_path  # Return the path to the created archive


def unique_filename(path):
    if not os.path.exists(path):
        return path  # It's already unique

    # Split the path into base and extension
    base, ext = os.path.splitext(path)
    counter = 1
    while True:
        # Append a counter to the base name to make it unique
        new_path = str(base + counter + ext)
        if not os.path.exists(new_path):
            return new_path
        counter += 1


# does the encryption process
def encryption_execute(plaintext, password, aes_mode, progress_queue):
    # check if the user chose 128 or 256
    if aes_mode == 128:
        length = 32
        key_size = 16
        aes_finder = b'\x00'
    else:
        length = 48
        key_size = 32
        aes_finder = b'\x01'

    # generate random salt
    salt = os.urandom(16)

    # get the encryption key and HMAC key from the password and salt
    key = aes.password_encode(password, salt, length)

    key_actual = key[:key_size]  # AES key
    key_hmac = key[key_size:]  # HMAC key

    # Initiate AES encryption
    aes_key = aes(key_actual, aes_mode)

    # progress callback function
    def progress(iteration, blocks):
        if blocks == 0:
            return
        percentage = (iteration / blocks) * 100
        progress_queue.put(("progress", percentage))

    # encrypt plaintext
    ciphertext = aes_key.encrypt(plaintext, salt,
                                 progress_callback=progress)  # progress_callback=self.progress_update

    # HMAC for integrity validation
    hmac_data = aes_finder + ciphertext  # Include aes_finder
    hmac_tag = hmac.new(key_hmac, hmac_data, hashlib.sha256).digest()

    # combine AES mode, ciphertext and HMAC
    encrypted_data = aes_finder + ciphertext + hmac_tag

    return encrypted_data


def encrypt(aes_mode, password, files, archive, progress_queue):
    try:
        if archive:
            # does archiving
            if len(files) == 1:
                # only one item
                if os.path.isdir(files[0]):
                    # compress folder
                    archive_path = folder_compression(files[0], progress_queue)
                else:
                    # compress single file
                    archive_path = files[0]
            else:
                # compress multiple files
                archive_path = file_compression(files, progress_queue)

            if not archive_path:
                progress_queue.put(("ERROR", "Compression failed"))
                return

            progress_queue.put(("info", "Archive created successfully"))

            # encrypted file name
            head, tail = os.path.split(archive_path)
            name, extension = os.path.splitext(tail)
            # new encryption file
            new_filename = os.path.join(head, name + "_encrypted" + extension)
            new_filename = new_filename.replace("_decrypted", "")
            # if the file name exists
            new_filename = unique_filename(new_filename)

            # read the archive path
            with open(archive_path, 'rb') as f:
                plaintext = f.read()

            # encrypt the plaintext
            encrypted_data = encryption_execute(plaintext, password, aes_mode, progress_queue)
            try:
                # write the encrypted data into the new file
                with open(new_filename, 'wb') as f:
                    f.write(encrypted_data)

                # remove the original file
                os.remove(archive_path)

            except Exception as error:
                progress_queue.put(("ERROR", str(error)))
                return
            progress_queue.put(("ALL_DONE", 1))

        else:
            # total selected files
            total_files = len(files)

            for index, item in enumerate(files, start=1):
                if os.path.isdir(item):
                    # compress folder
                    archive_path = folder_compression(item, progress_queue)
                else:
                    # compress files
                    archive_path = file_compression([item], progress_queue)

                if not archive_path:
                    progress_queue.put(("ERROR", "Compression failed " + str(item)))
                    continue
                # read the files
                with open(archive_path, 'rb') as f:
                    plaintext = f.read()

                # splits the file name
                head, tail = os.path.split(archive_path)
                name, extension = os.path.splitext(tail)

                # new file name
                new_filename = os.path.join(head, name + "_encrypted" + extension)
                new_filename = new_filename.replace("_decrypted", "")
                new_filename = unique_filename(new_filename)

                # performs encryption
                encrypted_data = encryption_execute(plaintext, password, aes_mode, progress_queue)

                try:
                    # save the encrypted data into the new file
                    with open(new_filename, 'wb') as f:
                        f.write(encrypted_data)

                    # remove the original file
                    os.remove(archive_path)

                except Exception as error:
                    progress_queue.put(("ERROR", str(error)))
                    return

                progress_queue.put(("FILE_DONE", index, total_files))

            progress_queue.put(("ALL_DONE", total_files))
    except Exception as error:
        progress_queue.put(("ERROR", str(error)))


# Encryption UI
class EncryptUI(BaseUI):
    # initiate Base to get custom widget from it
    def __init__(self, master, app):
        super().__init__(master)
        # reference to the main app class
        self.app = app
        # File path for images
        self.file_path = "images/encrypt/"

        # check for motion and key strokes to reset the session timer
        self.master.bind("<Motion>", lambda _: self.app.reset_session_timer())
        self.master.bind("<Key>", lambda _: self.app.reset_session_timer())

        # place listbox for selected files
        self.listbox.place(x=965, y=465)
        self.listbox.bind("<BackSpace>", self.delete_selected_item)

        # Password Entry
        self.get_password = self.entry(470, 444, 400, 82, "Password", "#9B62CA", "*")
        self.get_confirm_password = self.entry(470, 566, 400, 82, "Confirm Password", "#A063B4", "*")

        # AES mode selection
        self.aes_mode = IntVar(value=128)
        self.aes_selection_mode()

        # progress bar
        self.encrypt_progress = self.progress_bar(200, 895, "#AD657C", "#AB88FF")
        self.encrypt_progress.set(0)

        # variable to store status text
        self.status_text = None

        # images
        self.add_image(self.canvas, 722, 512, "background_img.png", self.file_path)
        self.add_image(self.canvas, 720, 112, "title_image.png", self.file_path)
        self.add_image(self.canvas, 720, 262, "encryption_title_background.png", self.file_path)
        self.add_image(self.canvas, 146, 184, "navigation_background.png", self.file_path)
        self.add_image(self.canvas, 262, 482, "enter_passwd_text.png", self.file_path)
        self.add_image(self.canvas, 262, 604, "confirm_password_text.png", self.file_path)
        self.add_image(self.canvas, 1169.0, 677.0, "selected_password_background.png", self.file_path)
        self.add_image(self.canvas, 1170.0, 425.0, "selected_password_label_background.png", self.file_path)

        # title heading
        self.canvas.create_text(
            560, 200, anchor="nw",
            text="Encryption",
            fill="#FFFFFF",
            font=("Khula Bold", 70)
        )

        # selected files/folder heading
        self.canvas.create_text(
            1020,400,
            anchor="nw",
            text="Selected Files/Folders",
            fill="#000000",
            font=("Khula SemiBold", 30 * -1),
        )

        # buttons

        self.encrypt_button = self.add_button(466, 773, 433, 90,
                                              "Encrypt",
                                              self.password_validation,
                                              "#AA6583", "#b84f4f")  # Start Encrypt button

        self.choose_file_button = self.add_button(410, 683, 214, 63,
                                                  "Choose Files",
                                                  self.add_file_to_list,
                                                  "#A464A0",
                                                  "#FF9898")    # Choose files button

        self.choose_folder_button = self.add_button(650, 683, 214, 63,
                                                    "Choose Folders",
                                                    self.add_folder_to_list,
                                                    "#A463A2", "#FF9898")   # Choose Folder button

        self.faq_nav_button = self.add_button(12, 258, 262, 88,
                                              "FAQ/Help",
                                              self.app.faq_ui,
                                              "#6949B4", "#D9D9D9")  # FAQ navigation button

        self.decrypt_nav_button = self.add_button(12, 48, 262, 90,
                                                  "Decrypt",
                                                  self.app.decrypt_ui,
                                                  "#6949B4", "#D9D9D9")  # Decrypt UI Navigation Button

        self.password_vault_nav_button = self.add_button(12, 152, 262, 89,
                                                         "Password Vault",
                                                         self.app.password_vault_login_ui,
                                                         "#6949B4", "#D9D9D9")  # Password Vault Navigation Button

        self.clear_all_button = self.add_button(1065, 895, 214, 63,
                                                "Clear All",
                                                self.clear_listbox,
                                                "#FFFFFF", "#FF9898")   # Clear listbox Navigation Button

    # enable/disable buttons
    def enable_disable_button(self, text_command):
        button_lists = [
            self.encrypt_button,
            self.choose_file_button,
            self.choose_folder_button,
            self.faq_nav_button,
            self.decrypt_nav_button,
            self.password_vault_nav_button,
            self.clear_all_button,

        ]
        for button in button_lists:
            button.configure(state=text_command)

    def aes_selection_mode(self):
        # label to display selected AES mode
        self.aes_label = self.label(470, 320, "Select AES Mode: Currently Selected: " + str(self.aes_mode.get()),
                                    "#AB88FF", "#9561E4")

        def update_label(*args):
            # update the label when the AES mode changes
            self.aes_label.configure(text="Select AES Mode: Currently Selected: " + str(self.aes_mode.get()))

        # bind the update function to the AES mode variable
        self.aes_mode.trace_add("write", update_label)

        # radio buttons for AES-128 and AES-256
        self.radio_button(550, 370, "AES-128", self.aes_mode, 128, "#D3495D", "#9762DB")
        self.radio_button(690, 370, "AES-256", self.aes_mode, 256, "#D3495D", "#9762DB")

    def password_delete(self):
        # clear the password and confirm password entry box
        self.get_password.delete(0, "end")
        self.get_confirm_password.delete(0, "end")

    def password_validation(self):
        password = self.get_password.get()
        confirm_password = self.get_confirm_password.get()

        # Check for empty fields
        if not password:
            messagebox.showerror("Error", "Please enter your password")
            self.get_password.focus_set()  # Focus the password field
            return  # Exit early

        if not confirm_password:
            messagebox.showerror("Error", "Please confirm your password")
            self.get_confirm_password.focus_set()
            return

        # Validate password strength
        error_message = None

        if len(password) < 8:
            error_message = "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            error_message = "Password must contain at least one number"
        if not any(c.islower() for c in password):
            error_message = "Password must contain at least one uppercase letter (A-Z)"
        if not any(c.isdigit() for c in password):
            error_message = "Password must contain at least one lowercase letter (a-z)"
        if not any(c in '!@#$%^&*()_+-=[]{};:,.<>?/' for c in password):
            error_message = "Password must contain at least one special character (e.g., @, #, $)"

        if error_message:
            messagebox.showerror("Password Error", error_message)
            self.password_delete()  # Clear fields
            return

        # Check if passwords match
        if password != confirm_password:
            messagebox.showerror("Password Error", "Passwords do not match")
            self.password_delete()
            return

        # start encryption
        self.file_enc()

    def progress_update(self, iteration, total_blocks):
        if total_blocks == 0:
            return
        progress_percentage = (iteration / total_blocks) * 100  # Convert to percentage

        # update progress bar
        self.master.after(0, lambda: self.encrypt_progress.config(value=progress_percentage))

    def file_enc(self):
        if not self.selected_file:
            messagebox.showerror("Error", "No files or folders selected for encryption")
            return

        # check either to archive files:
        if os.path.isdir(self.selected_file[0]):
            archive = True
        else:
            if len(self.selected_file) > 1:
                info = messagebox.askyesno("Information", "Would you like to archive multiple files in one folder?")
                archive = info
            else:
                archive = False

        # disable buttons and entry boxes
        self.enable_disable_button("disabled")
        self.get_password.configure(state="disabled")
        self.get_confirm_password.configure(state="disabled")

        # set progress bar to 0
        self.encrypt_progress.set(0)

        self.progress_queue = multiprocessing.Queue()

        # get files, files and password from the user input
        files = self.selected_file
        password = self.get_password.get()
        aes_mode = self.aes_mode.get()

        # start encryption process in a separate process
        self.process = multiprocessing.Process(target=encrypt,
                                               args=(aes_mode, password, files, archive, self.progress_queue))
        self.process.start()

        # start monitoring progress
        self.check_progress_queue()

    def check_progress_queue(self):
        try:
            while True:
                message = self.progress_queue.get_nowait()

                if message[0] == "progress":
                    percentage = message[1]

                    # update progress bar
                    fraction = float(percentage) / 100.0
                    self.encrypt_progress.set(fraction)
                    self.app.reset_session_timer()

                elif message[0] == "FILE_DONE":
                    file_index = message[1]
                    total_files = message[2]
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)

                    # display current files progress
                    self.status_text = self.canvas.create_text(580, 965, text="File " + str(file_index) + "/" + str(
                        total_files) + " Encrypted", fill="#FFFFFF", font=("Khula", 20), )

                elif message[0] == "ERROR":

                    # enables buttons and entry boxes
                    self.enable_disable_button("normal")
                    self.get_password.configure(state="normal")
                    self.get_confirm_password.configure(state="normal")

                    # show error message
                    messagebox.showerror("Error", message[1])
                    self.encrypt_progress.set(0)
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)
                        self.status_text = None

                elif message[0] == "ALL_DONE":

                    # Wait for child to exit
                    self.process.join()
                    self.process = None

                    # enables buttons and entry boxes
                    self.enable_disable_button("normal")
                    self.get_password.configure(state="normal")
                    self.get_confirm_password.configure(state="normal")

                    # show successful message
                    messagebox.showinfo("Successful Encryption", "Encryption has been successful")
                    self.encrypt_progress.set(0)

                    # clears password entry boxes and list box
                    self.password_delete()
                    self.clear_listbox()
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)
                        self.status_text = None

        except queue.Empty:
            pass

        if self.process is not None and self.process.is_alive():
            # continue monitoring progress
            self.master.after(100, self.check_progress_queue)
        else:

            pass
