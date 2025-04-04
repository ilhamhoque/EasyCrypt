from baseUI import BaseUI

class faq_ui(BaseUI):
    def __init__(self, master, app):
        # initialise base class for its custom widget
        super().__init__(master)
        # reference to the main application
        self.app = app

        # check for mouse and key movement to reset the session timer
        self.master.bind("<Motion>", lambda _: self.app.reset_session_timer())
        self.master.bind("<Key>", lambda _: self.app.reset_session_timer())

        self.file_path = "images/faq/"

        # images
        self.add_image(self.canvas, 723, 512, "background_img.png", self.file_path)
        self.add_image(self.canvas, 720, 112, "title_img.png", self.file_path)
        self.add_image(self.canvas, 720, 262, "encryption_title_background.png", self.file_path)
        self.add_image(self.canvas, 152, 180, "navigation_background.png", self.file_path)
        self.add_image(self.canvas, 720, 700, "faq_background.png", self.file_path)

        # title
        self.canvas.create_text(
            563, 200, anchor="nw",
            text="Help/FAQ",
            fill="#FFFFFF",
            font=("Khula Bold", 70)
        )

        # buttons
        self.add_button(16, 43, 266, 92,
                        "Encrypt",
                        self.app.encrypt_ui,
                        "#6949B4", "#D9D9D9")   # Encrypt Navigation

        self.add_button(16, 147, 266, 93,
                        "Decrypt",
                        self.app.decrypt_ui,
                        "#6949B4", "#D9D9D9")   # Decrypt Navigation

        self.add_button(16, 254, 266, 95,
                        "Password Vault",
                       self.app.password_vault_login_ui,
                        "#6949B4", "#D9D9D9")   # Password Vault Navigation

        #  FAQs
        faq = [
            ["What is the Purpose of this app?",
             "This encryption software is designed to be simple, free, and open-source for everyone, so that you can securely encrypt and keep their valuable information safe."
             " It secures files and folders using AES 128 and 256 encryption, promotes healthy password practice, and supports password storage."],

            ["How does this application differ from existing encryption tools?",
             "This program is open-source and cross-platform with built-in password storage."
             " This program focuses on ease of use so that encryption can become accessible to individuals small organisations."],

            ["What encryption method does this application use? ",
             "The application implemented the Advanced Encryption Standard (AES-128 and 256), a widely recognised encryption algorithm,"
             " adopted by governments and organisations globally to secure sensitive information."],

            ["Will the application store my encryption keys or passwords?",
             "The app has a zero-knowledge design, ensuring encryption and decryption can only be done on the client computer."
             " It doesn’t save or see users’ passwords or encryption keys, guaranteeing total privacy. "
             "The encryption software will be distributed as a native executable for Windows and macOS,"],
            ["Is this application secure against hacking attempts?",
             "The app follows security best practices with strong password enforcement, encrypted storage, secure key management, and rigorous internal testing. "
             "All encryption and decryption happens locally, preventing unauthorised access."],

        ]

        # Define text positioning (grid-like layout)
        start_x = 250  # Left margin for the first column
        start_y = 420  # Top margin for the first row
        col_width = 500  # Width of each column
        row_height = 170  # Height of each row
        container_width = 480  # Width of the text container

        # Iterate through the FAQ list and place items in the grid
        for index, (question, answer) in enumerate(faq):
            col = index % 2  # Determine the column (0 or 1)
            row = index // 2  # Determine the row

            x = start_x + col * col_width  # Calculate x based on column
            y = start_y + row * row_height  # Calculate y based on row

            text_bbox = self.canvas.bbox(
                self.canvas.create_text(
                    x, y, anchor="nw", text=question,
                    font=("Khula Bold", 18), width=container_width, fill="white"
                )
            )
            answer_y = text_bbox[3] + 10  # Add 10 pixels after the question
            self.canvas.create_text(
                x, answer_y, anchor="nw",
                text=answer, font=("Khula", 16),
                width=container_width,
                fill="white"
            )
