import customtkinter as ctk
from tkinter import PhotoImage, filedialog, Listbox
import sys
import os


class BaseUI:
    def __init__(self, master):
        # initiate BaseUI class with master window
        self.master = master

        # list of stored selected files
        self.selected_file = []

        # canvas widget for placing text and other widgets
        self.canvas = ctk.CTkCanvas(
            master,
            bg="#FFFFFF",  # background colour
            height=1024,    # canvas height
            width=1440,     # canvas width
            bd=0,   # border width
            highlightthickness=0,   # highlight border
            relief="ridge"  # relief style of the border
        )
        self.canvas.place(x=0, y=0)  # place canvas

        # store references to images to prevent garbage collection as dictionary
        self.image_references = {}

        # listbox widget to display selected files and folders
        self.listbox = Listbox(self.master, width=45, height=25)


    def get_listbox(self):
        # get all the selected files/folder
        return self.listbox.get(0, "end")

    def add_button(self, x, y, width, height, text, command, bg, fg):
        # custom button to the UI
        btn = ctk.CTkButton(
            self.master,
            bg_color=bg,    # background colour
            text=text,  # button text
            width=width,    # button width
            height=height,  # button height
            corner_radius=20,   # button radius
            font=("Khula", 32),  # font and size
            fg_color=fg,    # foreground colour
            text_color="black",  # button text colour
            command=command  # execute command when clicked
        )
        btn.place(x=x, y=y) # place button in the canvas
        return btn

    def entry(self, x, y, width, height, placeholder, bg, show=None):
        # custom input box widget in the UI
        entry = ctk.CTkEntry(
            self.master,
            placeholder_text=placeholder,   #placehold text
            width=width,    # input box width
            height=height,  # input box height
            corner_radius=25,   # input box radius
            font=("Khula", 19),  # font and size
            bg_color=bg,    #  background colour
            fg_color="white",  # foreground colour
            text_color="black",  # text colour
            show=show,  # show text
            border_width=1,  # border width
        )
        entry.place(x=x, y=y)   # place input box widget
        return entry

    def text(self, x, y, fg,bc, width, height):
        # custom text widget to the UI
        text = ctk.CTkTextbox(
            self.master,
            fg_color=fg,    # foreground
            border_color = bc,  # border colour
            width=width,    # width
            height=height,  # height
            font=("Khula Bold", 24),    # font and size
            text_color="black", # text colour
            corner_radius=10,   # textbox radius
            bg_color="#6949B4"  # background colour
        )
        text.place(x=x, y=y)    # place textbox
        return text

    def label(self, x, y, text, fg, bg):
        # custom label widget to the UI
        label = ctk.CTkLabel(
            self.master,
            text=text,  # text
            font=("Khula", 26),  # font and size
            corner_radius=10,   # radius
            fg_color=fg,    # foreground
            bg_color=bg,    # background
            text_color="black",  # text colour

        )
        label.place(x=x, y=y)   # place label
        return label

    def radio_button(self, x, y, text, variable, value, fg, bg):
        # custom radio button
        radio_button = ctk.CTkRadioButton(
            self.master,
            text=text,  # text
            variable=variable,  # var store the selected value
            value=value,    # value links with the button
            font=("Khula", 28), # font and size
            fg_color=fg,    # foreground
            bg_color=bg,    # background
            text_color="black", # text colour
        )
        radio_button.place(x=x, y=y)    # place radio button
        return radio_button

    def progress_bar(self, x, y, bg, fg):
        # custom progress bar
        progress_bar = ctk.CTkProgressBar(
            self.master,
            orientation='horizontal',   # orientation of the bar
            mode='determinate',  # mode of progress
            width=700,  # width
            height=30,  # height
            corner_radius=10,   # radius
            fg_color=fg,    # foreground
            bg_color=bg,    # background
        )
        progress_bar.place(x=x, y=y)    # place progress bar
        return progress_bar

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS  # This is where py2app unpacks resources
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def add_image(self, canvas, x, y, file_name, file_path):
        full_path = self.resource_path(os.path.join(file_path, file_name))
        img = PhotoImage(file=full_path)
        self.image_references[file_name] = img
        canvas.create_image(x, y, image=img)
        return img

    def select_file(self):
        # open file dialog so user can select one or more file
        file_path = filedialog.askopenfilenames(title="Select a File", multiple=True)
        return file_path

    def select_folder(self):
        # open file dialoag so user can select folders
        folder_path = filedialog.askdirectory(title="Select a Folder")
        return folder_path

    def clear_listbox(self):
        # clears the list of selected files/folder
        self.listbox.delete(0, "end")
        self.selected_file.clear()

    def delete_selected_item(self, event=None):
        # delete selected item from the list box
        selected_items = self.listbox.curselection()
        if selected_items:
            for index in reversed(selected_items):
                self.listbox.delete(index)

    def add_file_to_list(self):
        # add selected files to the list box
        selected_file_path = self.select_file()
        if selected_file_path:
            for file_path in selected_file_path:
                self.listbox.insert("end", f"File: {file_path}")
                self.selected_file.append(file_path)

    def add_folder_to_list(self):
        # add selected folder in the list box
        selected_folder_path = self.select_folder()
        if selected_folder_path:
            self.listbox.insert("end", f"Folder: {selected_folder_path}")
            self.selected_file.append(selected_folder_path)

