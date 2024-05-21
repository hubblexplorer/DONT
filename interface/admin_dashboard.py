import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import os
import sys

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)

# Adicionar caminho para o keys_rsa.py
resources_dir = os.path.abspath(os.path.join(parent_dir, 'resources/rsa_sign'))
sys.path.append(resources_dir)

from api.api_db import Database  
from keys_rsa import encrypt_message, generate_rsa_keypair  

class AdminDashboard:
    def __init__(self, master):
        self.master = master
        master.title("Admin Dashboard")

        self.create_widgets()

    def create_widgets(self):
        # Criar frame para opções de administração
        self.frame = ttk.Frame(self.master)
        self.frame.pack(padx=10, pady=10, fill='x', expand=True)

        # Botão para registrar novo usuário
        self.register_user_button = ttk.Button(self.frame, text="Registrar Novo Usuário", command=self.register_user_interface)
        self.register_user_button.pack(fill='x', pady=5)

        # Botão para criar comissão
        self.create_commission_button = ttk.Button(self.frame, text="Criar Comissão", command=self.create_commission_interface)
        self.create_commission_button.pack(fill='x', pady=5)

        # Botão para criar eleição
        self.create_election_button = ttk.Button(self.frame, text="Criar Eleição", command=self.create_election_interface)
        self.create_election_button.pack(fill='x', pady=5)

    def register_user_interface(self):
        self.new_window = tk.Toplevel(self.master)
        self.new_window.title("Registrar Novo Usuário")

        self.label_username = ttk.Label(self.new_window, text="Nome de Usuário:")
        self.label_username.pack(padx=5, pady=5)

        self.entry_username = ttk.Entry(self.new_window)
        self.entry_username.pack(padx=5, pady=5)

        self.label_password = ttk.Label(self.new_window, text="Senha:")
        self.label_password.pack(padx=5, pady=5)

        self.entry_password = ttk.Entry(self.new_window, show='*')
        self.entry_password.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Registrar", command=self.register_user)
        self.submit_button.pack(padx=5, pady=5)

    def register_user(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if username and password:
            response = Database.register_user(username, password)
            if response.success:
                messagebox.showinfo("Sucesso", "Usuário registrado com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")

    def create_commission_interface(self):
        self.new_window = tk.Toplevel(self.master)
        self.new_window.title("Criar Comissão")

        self.label_commission_name = ttk.Label(self.new_window, text="Nome da Comissão:")
        self.label_commission_name.pack(padx=5, pady=5)

        self.entry_commission_name = ttk.Entry(self.new_window)
        self.entry_commission_name.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Criar", command=self.create_commission)
        self.submit_button.pack(padx=5, pady=5)

    def create_commission(self):
        commission_name = self.entry_commission_name.get()

        if commission_name:
            response = Database.create_commission(commission_name)
            if response.success:
                messagebox.showinfo("Sucesso", "Comissão criada com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")

    def create_election_interface(self):
        self.new_window = tk.Toplevel(self.master)
        self.new_window.title("Criar Eleição")

        self.label_election_name = ttk.Label(self.new_window, text="Nome da Eleição:")
        self.label_election_name.pack(padx=5, pady=5)

        self.entry_election_name = ttk.Entry(self.new_window)
        self.entry_election_name.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Criar", command=self.create_election)
        self.submit_button.pack(padx=5, pady=5)

    def create_election(self):
        election_name = self.entry_election_name.get()

        if election_name:
            response = Database.create_election(election_name)
            if response.success:
                messagebox.showinfo("Sucesso", "Eleição criada com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")

def start_admin_dashboard():
    root = tk.Tk()
    app = AdminDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    start_admin_dashboard()
