import tkinter as tk
from tkinter import messagebox
import re

class RegisterWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root, background="#212121")
        self.geometry("200x400")
        self.resizable(False, False)
        self.title("Register")
        self.app = app

        # Username
        self.username_label = tk.Label(self, text="Username", background="#212121", foreground="#ffffff")
        self.username_label.pack(padx=10, pady=15)
        self.username_entry = tk.Entry(self)
        self.username_entry.pack(padx=10, pady=15)

        # Password
        self.password_label = tk.Label(self, text="Password", background="#212121", foreground="#ffffff")
        self.password_label.pack(padx=10, pady=15)
        self.password_entry = tk.Entry(self)
        self.password_entry.pack(padx=10, pady=15)

        # Repeat Password
        self.password_label_r = tk.Label(self, text="Repeat Password", background="#212121", foreground="#ffffff")
        self.password_label_r.pack(padx=10, pady=15)
        self.password_entry_r = tk.Entry(self)
        self.password_entry_r.pack(padx=10, pady=15)

        button = tk.Button(self, text="Register", command=self.register)
        button.pack(padx=10, pady=30)

    def register(self):
        user = self.username_entry.get()
        password = self.password_entry.get()
        if not self.is_valid(password):
            messagebox.showerror("Error", "Password must be at least 8 characters long, have at least one uppercase letter and one special character")
            return
        try:
            if self.password_entry.get() != self.password_entry_r.get():
                messagebox.showerror("Error", "Passwords don't match")
            else:
                self.app.api.register(self.username_entry.get(), self.password_entry.get())
                messagebox.showinfo("Success", "User registered successfully")
                self.destroy()
        except Exception as e:
            print(e)
            messagebox.showerror("Error", "Error registering user")

    def is_valid(self, password) -> bool:
        pat = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[$@$!%*?&])([A-Za-z\d$@$!%*?&]|[^ ]){12,}$'
        return bool(re.match(pat, password))