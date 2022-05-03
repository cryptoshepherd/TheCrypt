import sqlalchemy as db
from sqlalchemy.sql import func
from sqlalchemy.dialects import sqlite
from os import path
import tkinter as tk
import tkinter as ttk
from tkinter import *
from tkinter import messagebox
from tkinter.simpledialog import askstring
from PIL import Image, ImageTk
import pwd_strenght_check
import pwd_master

metadata_obj = db.MetaData()

the_crypt = db.Table('the_crypt', metadata_obj,
    db.Column('id', db.Integer, primary_key=True),
    db.Column('username', db.String(30)),
    db.Column('password', db.String(50)),
    db.Column('date_created', db.DateTime(timezone=True), default=func.now()),
    db.Column('url', db.String(50))
)

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title('The Crypt')
        self.image = Image.open('thecrypt.jpg')
        self.photo = ImageTk.PhotoImage(self.image)
        self.create_widgets()
        
    def create_widgets(self):
        DB_NAME = 'TheCrypt.db'
        engine = db.create_engine(f'sqlite:///{DB_NAME}')

        if not path.exists(f"./{DB_NAME}"):
            metadata_obj.create_all(engine)
        
        self.v1 = tk.IntVar()
        self.alpha_check = tk.IntVar()
        self.special_check = tk.IntVar()

        # Create an image Label
        self.img_label = ttk.Label(image=self.photo, anchor=CENTER)
        self.img_label.image = self.photo

        self.img_label.grid(row=0, column=1)  

        # label
        ttk.Label(text='User:').grid(row=10, column=0, sticky='w')
        ttk.Label(text='Passwd: ').grid(row=11, column=0, sticky='w')
        ttk.Label(text='URL:').grid(row=12, column=0, sticky='w')
        ttk.Label(text='User:').grid(row=14, column=0, sticky='w')
        ttk.Label(text='TheCrypt:').grid(row=15, column=0, sticky='w')
        ttk.Label(text='URL:').grid(row=16, column=0, sticky='w')
        ttk.Label(text='Lenght:').grid(row=17, column=0, sticky='w')
        ttk.Label(text='A-aZ-z').grid(row=18, column=0, sticky='w')
        ttk.Label(text='@#!*').grid(row=19, column=0, sticky='w')

        # User Entry
        self.user_entry = ttk.Entry(self, width=30)
        self.user_entry.grid(row=10, column=1, columnspan=2, padx=10, pady=10)

        # Password Entry
        self.passwd_entry = ttk.Entry(self, width=30)
        self.passwd_entry.grid(row=11, column=1, columnspan=2, padx=10, pady=10)

        # URL Entry
        self.url_entry = ttk.Entry(self, width=30)
        self.url_entry.grid(row=12, column=1, columnspan=2, padx=10, pady=10)

        # Second User
        self.user_two = ttk.Entry(self, width=30)
        self.user_two.grid(row=14, column=1, columnspan=2, padx=10, pady=10)

        # TheCrypt
        self.the_crypt = ttk.Entry(self, width=30, state=DISABLED)
        self.the_crypt.grid(row=15, column=1, columnspan=2, padx=10, pady=10)

        # Second URL
        self.url_two = ttk.Entry(self, width=30)
        self.url_two.grid(row=16, column=1, columnspan=2, padx=10, pady=10)


        # Slider Entry
        self.slide_entry = ttk.Scale(self, variable=self.v1, from_=12, to=32, orient=HORIZONTAL)
        self.slide_entry.grid(row=17, column=1)

        # # Checknutton
        self.alpha_entry = ttk.Checkbutton(self, variable=self.alpha_check, text='')
        self.alpha_entry.grid(row=18, column=1)

        # # Checkbutton
        self.special_entry = ttk.Checkbutton(self, variable=self.special_check, text='')
        self.special_entry.grid(row=19, column=1)

        # Password of choice Add Button
        self.send_button = ttk.Button(text='Add Custom', command=self.validate_data).grid(row=13, padx=5, pady=5, column=1, sticky='s')

        # The Crypt Passowrd Button
        self.send_button = ttk.Button(text='The Crypt', command=self.validate_data).grid(row=20, padx=5, pady=5, column=1, sticky='s')

    def askMe(self, slide):
        res = messagebox.askquestion('askquestion', f'Password is {slide} chars long, are you ok?')
        if res == 'yes':
            messagebox.showinfo('Response', 'You are ok')
        elif res == 'no':
            messagebox.showinfo('Response', 'You are not ok')
        else:
            messagebox.showwarning('error', 'Something went wrong!')

    def validate_data(self):
        user = self.user_entry.get()
        passwd = self.passwd_entry.get()
        if user != "":
            #print(user)
            if passwd != "":
                #print(passwd)
                data = pwd_strenght_check.password_check(passwd)
                if data:
                    master_password_input = askstring("Master Password", "Please provide the master password")
                    if len(master_password_input) > 0:
                        pwd_master.encrypt_password(master_password_input, data)
                    else:
                        messagebox.showwarning('error', 'Something went wrong!')
            else:
                messagebox.showerror('Error', 'User or password are missing!')
    
    


if __name__ == '__main__':
    app = App()
    app.mainloop()