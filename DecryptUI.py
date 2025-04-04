from baseUI import BaseUI  # baseUI custom widgets
from tkinter import messagebox
import os
import shutil
import multiprocessing
import queue
import zipfile
import hmac
import hashlib

# encryption algorithm
from Encrypt_Decrypt import aes


# generate unique filename if name already exists
def unique_filename(path):
    if not os.path.exists(path):
        return path  # It's already unique

    # split path into base and extension
    base, ext = os.path.splitext(path)
    counter = 1
    while True:
        # append a counter to the base name to make it unique
        new_path = str(base + counter + ext)

        if not os.path.exists(new_path):
            return new_path
        counter += 1


# get all files in a directory
def get_files_directory(directory):
    result = []
    for path in directory:
        if os.path.isdir(path):  # if the path is a directory
            # walk through the directory and its sub-directories
            for root, dirs, files in os.walk(path):
                for filename in files:
                    # only include files with "_encrypted" in their name
                    if "_encrypted" in filename:
                        full_path = os.path.join(root, filename)
                        result.append(full_path)
        else:
            # if the path is a file
            result.append(path)
    return result


# Decrypts the file using AES encryption
def decrypt(password, file, progress_queue):
    try:
        total_files = len(file)  # total number of selected files

        # iterate over each files
        for file_index, path in enumerate(file, start=1):
            # split path into dictionary and filename
            head, tail = os.path.split(path)

            # splits tail into name and extension
            name = os.path.splitext(tail)[0]
            extension = os.path.splitext(tail)[1]

            # open the encrypted file
            with open(path, 'rb') as f:
                data = f.read()

            # check if the file is too small to be valid
            if len(data) < 81:  # aes_mode(1) + salt (16) + iv (16) + 1 block (16) + HMAC (32)
                progress_queue.put(("invalid_file_format", "Invalid file format"))
                return

            # check for the AES mode from the 1st byte
            aes_finder = data[0:1]

            if aes_finder == b'\x00':
                aes_mode = 128
                length = 32
                key_size = 16

            elif aes_finder == b'\x01':
                aes_mode = 256
                length = 48
                key_size = 32
            else:
                progress_queue.put(("Key_Decryption_Error", "key decryption error"))
                return

            # extract ciphertext, salt, IV and HMAC
            ciphertext_salt_iv = data[1:-32]

            stored_hmac = data[-32:]  # Last 32 bytes are HMAC

            # file format validation
            if len(ciphertext_salt_iv) < 16 + 16:
                progress_queue.put(("invalid_file_format", "invalid file format"))
                return

            # extract salt
            salt = ciphertext_salt_iv[0:16]  # 1st 16 bytes

            # get decryption key and HMAC key from the password and salt
            try:
                decrypt_password = aes.password_encode(password, salt, length)
            except Exception as e:
                progress_queue.put(("Key_Decryption_Error", str(e)))
                return

            aes_key = decrypt_password[:key_size]  # AES key
            hmac_key = decrypt_password[key_size:]  # HMAC key

            # update progress for progress bar
            def progress(iteration, blocks):
                if blocks == 0:
                    return
                percentage = (iteration / blocks) * 100
                progress_queue.put(("progress", percentage))

            # HMAC integrity check
            hmac_data = aes_finder + ciphertext_salt_iv  # Include AES mode byte
            computed_hmac = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()

            # verify HMAC to ensure data integrity
            if not hmac.compare_digest(computed_hmac, stored_hmac):
                progress_queue.put(("Error_corrupted", "hmac check failed"))
                return

            # Decrypt data
            decrypt_data = aes(aes_key, aes_mode)
            try:
                decryption = decrypt_data.decrypt(ciphertext_salt_iv, progress_callback=progress)

            except Exception as e:
                progress_queue.put(("Error_failed", str(e)))
                return

            # write decrypted data in a temporary file
            tmp_path = path + ".tmp"
            with open(tmp_path, 'wb') as f:
                f.write(decryption)

            # replace temporary file with encrypted file
            os.replace(tmp_path, path)

            # create final name for the decrypted file
            final_name = os.path.join(head, name + "_decrypted" + extension)
            final_name = final_name.replace("_encrypted", "")
            final_name = unique_filename(final_name)

            # rename the file to the final name
            os.rename(path, final_name)

            # if the file is a ZIP, then UNZIP it
            try:
                with zipfile.ZipFile(final_name, 'r') as zip_ref:
                    extract_path = os.path.join(head, name + "_decrypted")
                    zip_ref.extractall(extract_path)

                # move extracted files to the original directory
                if os.path.isdir(extract_path):
                    for item in os.listdir(extract_path):
                        src = os.path.join(extract_path, item)
                        dst = os.path.join(head, item)
                        shutil.move(src, dst)

                    # remove the zip folder
                    shutil.rmtree(extract_path)

                # remove zip file
                os.remove(final_name)

            # skip if the file is not a zip
            except zipfile.BadZipFile:
                pass

                # notify progress queue
            progress_queue.put(("FILE_DONE", file_index, total_files))

        progress_queue.put(("ALL_DONE", total_files))

    except Exception as e:
        progress_queue.put(("Error_failed", str(e)))


# Decryption UI

class DecryptUI(BaseUI):
    def __init__(self, master, app):
        # initiate BaseUI for the custom widget
        super().__init__(master)
        # reference to the main app class
        self.app = app

        # reset session time if motion and key stroke detected
        self.master.bind("<Motion>", lambda _: self.app.reset_session_timer())
        self.master.bind("<Key>", lambda _: self.app.reset_session_timer())

        # File path for images
        self.file_path = "images/decrypt/"

        # place the listbox of the selected files
        self.listbox.place(x=965, y=450)
        self.listbox.bind("<BackSpace>", self.delete_selected_item)

        # password variable
        self.password = self.entry(517, 459, 361, 78, "Password", "#9B62CA", "*")

        # progress bar placing
        self.decrypt_progress = self.progress_bar(200, 895, "#AD657C", "#AB88FF")
        self.decrypt_progress.set(0)

        # variable to store status text
        self.status_text = None

        # images
        self.add_image(self.canvas, 722, 512, "background_img.png", self.file_path)
        self.add_image(self.canvas, 720, 112, "title_img.png", self.file_path)
        self.add_image(self.canvas, 720, 262, "decryption_title_background.png", self.file_path)
        self.add_image(self.canvas, 327, 492, "enter_passwd_text.png", self.file_path)
        self.add_image(self.canvas, 151, 184, "menu_background.png", self.file_path)
        self.add_image(self.canvas, 1170.0, 662.0, "selected_files_background.png", self.file_path)
        self.add_image(self.canvas, 1171.0, 410.0, "selected_files_label_background.png", self.file_path)

        # buttons
        self.decrypt_button = self.add_button(219, 705, 580, 90,
                                              "Decrypt", self.file_enc,
                                              "#AA6583", "#b84f4f")  # Encrypt Button

        self.choose_file_button = self.add_button(265, 577, 214, 63,
                                                  "Choose Files", self.add_file_to_list,
                                                  "#A464A0", "#FF9898")  # Select File Button

        self.choose_folder_button = self.add_button(513, 577, 214, 63,
                                                    "Choose Folders",
                                                    self.add_folder_to_list,
                                                    "#A463A2", "#FF9898")   # Select Folder Button

        self.faq_nav_button = self.add_button(17, 255, 266, 91,
                                              "FAQ/Help",
                                              self.app.faq_ui,
                                              "#6949B4", "#D9D9D9")  # FAQ Navigation Button

        self.encrypt_nav_button = self.add_button(17, 45, 266, 92,
                                                  "Encrypt",
                                                  self.app.encrypt_ui,
                                                  "#6949B4", "#D9D9D9")  # Encrypt UI Navigation

        self.password_nav_vault_button = self.add_button(17, 148, 266, 91,
                                                         "Password Vault",
                                                         self.app.password_vault_login_ui,
                                                         "#6949B4", "#D9D9D9")   # Password Vault Navigation

        self.clear_all_button = self.add_button(1065, 880, 214, 63,
                                                "Clear All",
                                                self.clear_listbox,
                                                "#FFFFFF", "#FF9898")    # Clear all listbox

        # Add title text
        self.canvas.create_text(
            560, 200, anchor="nw",
            text="Decryption",
            fill="#FFFFFF",
            font=("Khula Bold", 70)
        )

        # title text for selected files/folder
        self.canvas.create_text(
            1020,
            390,
            anchor="nw",
            text="Selected Files/Folders",
            fill="#000000",
            font=("Khula SemiBold", 30 * -1),
        )

    # delete password entry box
    def delete_password(self):
        self.password.delete(0, "end")

    # disable all of the buttons
    def enable_disable_button(self, text_command):
        button_lists = [
            self.decrypt_button,
            self.choose_file_button,
            self.choose_folder_button,
            self.faq_nav_button,
            self.encrypt_nav_button,
            self.password_nav_vault_button,
            self.clear_all_button,

        ]
        for button in button_lists:
            button.configure(state=text_command)

    # file decryption
    def file_enc(self):
        # show error if selected files is empty
        if not self.selected_file:
            messagebox.showerror("Error", "No files or folders selected for encryption")
            return

        files = self.selected_file

        # if selected path is a directory then get all the files in it
        if os.path.isdir(self.selected_file[0]):
            files = get_files_directory(self.selected_file)

            if not files:
                messagebox.showerror("Error", "No files or folders selected for encryption")
                return

        # disable buttons and password field during decryption
        self.enable_disable_button("disabled")
        self.password.configure(state="disabled")

        # get the password from password entry box
        password = self.password.get()
        self.decrypt_progress.set(0)

        # start the queue
        self.progress_queue = multiprocessing.Queue()

        # start decryption process in a separate process
        self.process = multiprocessing.Process(target=decrypt, args=(password, files, self.progress_queue))
        self.process.start()
        self.check_progress_queue()

    # check the progress queue for updates
    def check_progress_queue(self):
        try:
            while True:
                message = self.progress_queue.get_nowait()


                if message[0] == "progress":
                    percentage = message[1]

                    # progress number divided into fraction because customtkinter progressbar
                    # supports 0 to 1 number.
                    fraction = float(percentage) / 100.0
                    self.decrypt_progress.set(fraction)

                    # reset the timer for the password storage if logged in
                    self.app.reset_session_timer()

                # if one file is decrypted
                elif message[0] == "FILE_DONE":
                    file_index = message[1] # number of files decrypted
                    total_files = message[2]    # total files

                    # delete old text
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)

                    # insert text in UI
                    self.status_text = self.canvas.create_text(580, 965, text="File " + str(file_index) + "/" + str(
                        total_files) + " Decrypted",
                                                               fill="#FFFFFF",
                                                               font=("Khula", 20), )

                # error message
                elif message[0] in ("Key_Decryption_Error", "invalid_file_format", "Error_corrupted", "Error_failed"):
                    messagebox.showerror("Error", message[1])

                    # clears listbox if file is invalid
                    if message[0] == "invalid_file_format":
                        self.clear_listbox()
                    else:
                        # delete entry password
                        self.delete_password()

                    # enables all the buttons and entry boxes
                    self.password.configure(state="normal")
                    self.enable_disable_button("Normal")

                    # progress bar set to 0
                    self.decrypt_progress.set(0)

                    # delete status text
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)
                        self.status_text = None

                # when all the selected files have been decrypted
                elif message[0] == "ALL_DONE":


                    # Wait for child to exit
                    self.process.join()
                    self.process = None

                    # enable buttons and password entry boxes
                    self.enable_disable_button("normal")
                    self.password.configure(state="normal")

                    # notify user
                    messagebox.showinfo("Successful Decryption", "Decryption has been successful")

                    # set progress bar to 0
                    self.decrypt_progress.set(0)

                    # delete password entry box, selected files and status text
                    self.delete_password()
                    self.clear_listbox()
                    if self.status_text is not None:
                        self.canvas.delete(self.status_text)
                        self.status_text = None

        # if queue trying to get something but is empty
        except queue.Empty:
            pass

        # check if the decryption process is still running
        if self.process is not None and self.process.is_alive():
            # schedule check_progress_queue to run after 100 milliseconds
            self.master.after(100, self.check_progress_queue)
        else:
            # if the decryption process is not running
            pass
