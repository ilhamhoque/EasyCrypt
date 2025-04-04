from baseUI import BaseUI


class homepageUI(BaseUI):
    def __init__(self, master, app):
        # initialise base class for custom widgets
        super().__init__(master)
        self.app = app
        # reference to the main application
        # Ensure the correct file path using resource_path()
        self.file_path = "images/home"

        # Debugging: Print file paths
        print(f"📂 Homepage Images Path: {self.file_path}")

        # Add background and title images
        self.add_image(self.canvas, 722, 512, "background_img.png", self.file_path)
        self.add_image(self.canvas,720, 139, "title_image.png", self.file_path)

        # Create buttons with navigation
        self.add_button(505, 338, 420, 95,
                        "Encrypt",
                        self.app.encrypt_ui,
                        "#9761DC", "#D9D9D9")

        self.add_button(505, 454, 420, 95,
                        "Decrypt",
                        self.app.decrypt_ui,
                        "#9C62C3", "#D9D9D9")

        self.add_button(505, 570, 420, 95,
                        "Password Vault",
                        self.app.password_vault_login_ui,
                        "#A163AB", "#D9D9D9")

        self.add_button(505, 686, 420, 95,
                        "FAQ/Help",
                        self.app.faq_ui,
                        "#A66495", "#D9D9D9")



