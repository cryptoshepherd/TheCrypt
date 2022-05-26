from sqlalchemy import create_engine
from sqlalchemy.orm.session import sessionmaker
from models import Crypt, Base
from os import path
import tkinter as tk
from tkinter import *
from tkinter import messagebox
from tkinter.simpledialog import askstring
import pwd_strenght_check
import pwd_master
import pwd_gen


class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.vertscroll = None
        self.textbox = None
        self.search_result = None
        self.button_search_user = None
        self.user_search = None
        self.button_search_url = None
        self.url_search = None
        self.slide_entry_crypt = None
        self.v1 = None
        self.button_crypt = None
        self.url_entry_crypt = None
        self.password_entry_crypt = None
        self.user_entry_crypt = None
        self.button_custom = None
        self.url_entry_custom = None
        self.password_entry_custom = None
        self.user_entry_custom = None
        self.title('The Crypt')
        self.master = self.geometry('980x900')
        # self.image = Image.open('thecrypt.jpg')
        # zoom = 0.9
        # pixels_x, pixels_y = tuple([int(zoom * x) for x in self.image.size])
        # self.photo = ImageTk.PhotoImage(self.image.resize((pixels_x, pixels_y)))
        self.create_widgets()

    def create_widgets(self):

        # Frame Image
        # panel = ttk.Label(image=self.photo)
        # panel.image = self.photo
        # panel.grid(column=1, row=0)

        # Frame Custom
        frame1_label = tk.Label(text="Custom")
        frame1 = tk.LabelFrame(labelwidget=frame1_label, labelanchor='nw', height=220, width=260)
        frame1.grid(column=0, row=1, padx=20, pady=20)
        frame1.grid_propagate(0)

        # Frame Crypt
        frame2_label = tk.Label(text="Crypt")
        frame2 = tk.LabelFrame(labelwidget=frame2_label, labelanchor='nw', height=220, width=270)
        frame2.grid(column=1, row=1, padx=20, pady=20)
        frame2.grid_propagate(0)

        # Frame Search URL
        frame3_label = tk.Label(text="Search URL")
        frame3 = tk.LabelFrame(labelwidget=frame3_label, labelanchor=N, height=220, width=270)
        frame3.grid(column=0, row=4, padx=20, pady=20)
        frame3.grid_propagate(0)

        # Frame Search User
        frame4_label = tk.Label(text="Search User")
        frame4 = tk.LabelFrame(labelwidget=frame4_label, labelanchor=N, height=220, width=270)
        frame4.grid(column=1, row=4, padx=20, pady=20)
        frame4.grid_propagate(0)

        # Frame Search Result
        frame5_label = tk.Label(text="Search Results")
        frame5 = tk.LabelFrame(labelwidget=frame5_label, labelanchor='nw', height=240, width=600)
        frame5.grid(column=0, row=7, padx=20, pady=20)
        frame5.grid_propagate(0)

        # DB Engine
        DB_NAME = 'TheCrypt.db'
        global engine
        engine = create_engine(f'sqlite:///{DB_NAME}')

        # DB Creation
        if not path.exists(f"./{DB_NAME}"):
            Base.metadata.create_all(engine)

        self.v1 = tk.IntVar()

        # Labels Custom
        label_user_custom = tk.Label(frame1, text='User:')
        label_user_custom.grid(column=0, row=0, ipadx=10, ipady=10)
        label_password_custom = tk.Label(frame1, text='Pwd:')
        label_password_custom.grid(column=0, row=1, ipadx=10, ipady=10)
        label_url_custom = tk.Label(frame1, text='URL:')
        label_url_custom.grid(column=0, row=2, ipadx=10, ipady=10)

        # Labels Crypt
        label_user_crypt = tk.Label(frame2, text='User:')
        label_user_crypt.grid(column=1, row=0, ipadx=10, ipady=10)
        label_password_crypt = tk.Label(frame2, text='Pwd:')
        label_password_crypt.grid(column=1, row=1, ipadx=10, ipady=10)
        label_url_crypt = tk.Label(frame2, text='URL:')
        label_url_crypt.grid(column=1, row=2, ipadx=10, ipady=10)
        label_slide_crypt = tk.Label(frame2, text='Length:')
        label_slide_crypt.grid(column=1, row=3, padx=10, ipady=10)

        # Labels Search
        label_url_search = tk.Label(frame3, text="URL:")
        label_url_search.grid(column=0, row=0, ipadx=10, ipady=10)
        label_user_search = tk.Label(frame4, text="User:")
        label_user_search.grid(column=1, row=0, ipadx=10, ipady=10)

        # Entries Custom
        self.user_entry_custom = tk.Entry(frame1, width=30)
        self.user_entry_custom.grid(column=1, row=0, ipadx=5, ipady=5)
        self.password_entry_custom = tk.Entry(frame1, width=30)
        self.password_entry_custom.grid(column=1, row=1, ipadx=5, ipady=5)
        self.url_entry_custom = tk.Entry(frame1, width=30)
        self.url_entry_custom.grid(column=1, row=2, ipadx=5, ipady=5)
        self.button_custom = tk.Button(frame1, text='Add', command=self.validate_pwd_custom)
        self.button_custom.grid(column=1, row=3, padx=5, pady=5)

        # Entries Crypt
        self.user_entry_crypt = tk.Entry(frame2, width=30)
        self.user_entry_crypt.grid(column=2, row=0, ipadx=5, ipady=5)
        self.password_entry_crypt = tk.Entry(frame2, width=30, state=DISABLED)
        self.password_entry_crypt.grid(column=2, row=1, ipadx=5, ipady=5)
        self.url_entry_crypt = tk.Entry(frame2, width=30)
        self.url_entry_crypt.grid(column=2, row=2, ipadx=5, ipady=5)
        self.slide_entry_crypt = tk.Scale(frame2, variable=self.v1, from_=12, to=32, orient=HORIZONTAL)
        self.slide_entry_crypt.grid(column=2, row=3)
        self.button_crypt = tk.Button(frame2, text='Add', command=self.validate_pwd_crypt)
        self.button_crypt.grid(column=2, row=4, padx=5, pady=5)

        # Entries Search:
        self.url_search = tk.Entry(frame3, width=30)
        self.url_search.grid(column=1, row=0, ipadx=5, ipady=5)
        self.button_search_url = tk.Button(frame3, text='Search...', command=self.search_url)
        self.button_search_url.grid(column=1, row=4, padx=5, pady=5)
        self.user_search = tk.Entry(frame4, width=30)
        self.user_search.grid(column=2, row=0, ipadx=5, ipady=5)
        self.button_search_user = tk.Button(frame4, text='Search...', command=self.search_user)
        self.button_search_user.grid(column=2, row=4, padx=5, pady=5)

        # Search Result
        text_font = "Comic Sans MS"
        self.textbox = tk.Text(frame5, height=16, width=90, font=(text_font, 10))
        self.vertscroll = tk.Scrollbar(frame5)
        self.textbox.config(yscrollcommand=self.vertscroll.set)
        self.textbox.grid(column=1, row=0)
        self.vertscroll.grid(column=2, row=0, sticky='NS')

    def validate_pwd_custom(self):
        user = self.user_entry_custom.get()
        passwd = self.password_entry_custom.get()
        url = self.url_entry_custom.get()
        if user != "":
            if passwd != "":
                data = pwd_strenght_check.password_check(passwd)
                if data:
                    master_password_input = askstring("Master Password", "Please provide the master password", show='*')
                    if len(master_password_input) > 0:
                        enc_pwd = pwd_master.encrypt_password(master_password_input, data)
                        Session = sessionmaker(bind=engine)
                        session = Session()
                        new_entry = Crypt(username=user, password=enc_pwd, url=url)
                        session.add(new_entry)
                        session.commit()
                    else:
                        messagebox.showwarning('error', 'Something went wrong!')
            else:
                messagebox.showerror('Error', 'User or password are missing!')
        else:
            messagebox.showerror('Error', 'Please provide a user!')

    def validate_pwd_crypt(self):
        user = self.user_entry_crypt.get()
        url = self.url_entry_crypt.get()
        if user != '':
            master_password_input = askstring("Master Password", "Please provide the master password", show='*')
            if len(master_password_input) > 0:
                password_length = self.slide_entry_crypt.get()
                print(password_length)
                res = messagebox.askyesno('Acknowledge',
                                          f"The selected password's length is {password_length}, are you ok ?")
                if res == True:
                    data = pwd_gen.password_gen(password_length)
                    print(data)
                    enc_pwd = pwd_master.encrypt_password(master_password_input, data)
                    print(enc_pwd)
                    Session = sessionmaker(bind=engine)
                    session = Session()
                    new_entry = Crypt(username=user, password=enc_pwd, url=url)
                    session.add(new_entry)
                    session.commit()
                elif res == False:
                    pass

    def search_frame_results(self, username, password, url, line_num, result_num):
        line_num = f"{line_num}.0"
        result = f'Result {result_num} Username: "{username}" Password: "{password}" Url: "{url}"\n'
        self.textbox.insert(line_num, result)

    def search_url(self):
        url = self.url_search.get()
        url_key = f'%{url}%'
        line_num = 0
        result_num = 0
        if url != '':
            master_password_input = askstring("Master Password", "Please provide the master password", show='*')
            Session = sessionmaker(bind=engine)
            session = Session()
            url_search = session.query(Crypt).with_entities(Crypt.username, Crypt.password, Crypt.url).filter(
                Crypt.url.like(url_key)).all()
            for result in url_search:
                encoded_ciphertext = result.password
                decoded_ciphertext = pwd_master.decrypt_password(master_password_input, encoded_ciphertext)
                line_num += 1
                result_num += 1
                username = result.username
                password = decoded_ciphertext.decode('UTF-8')
                url = result.url
                self.search_url_frame_results(username, password, url, str(line_num), str(result_num))
        else:
            res = messagebox.showerror("Please provide a valid URL")

    def search_user(self):
        user = self.user_search.get()
        user_key = f'%{user}%'
        line_num = 0
        result_num = 0
        if user != '':
            master_password_input = askstring("Master Password", "Please provide the master password", show='*')
            Session = sessionmaker(bind=engine)
            session = Session()
            user_search = session.query(Crypt).with_entities(Crypt.username, Crypt.password, Crypt.url).filter(
                Crypt.username.like(user_key)).all()
            for result in user_search:
                encoded_ciphertext = result.password
                decoded_ciphertext = pwd_master.decrypt_password(master_password_input, encoded_ciphertext)
                line_num += 1
                result_num += 1
                username = result.username
                password = decoded_ciphertext.decode('UTF-8')
                url = result.url
                self.search_frame_results(username, password, url, str(line_num), str(result_num))
        else:
            res = messagebox.showerror("Please provide a valid URL")


if __name__ == '__main__':
    app = App()
    app.mainloop()
