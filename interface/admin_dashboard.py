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

        # Botão para registar novo utilizador
        self.register_user_button = ttk.Button(self.frame, text="Registar Novo Utilizador", command=self.register_user_interface)
        self.register_user_button.pack(fill='x', pady=5)

        # Botão para criar comissão
        self.create_commission_button = ttk.Button(self.frame, text="Criar Comissão", command=self.create_commission_interface)
        self.create_commission_button.pack(fill='x', pady=5)

        # Botão para criar eleição
        self.create_election_button = ttk.Button(self.frame, text="Criar Eleição", command=self.create_election_interface)
        self.create_election_button.pack(fill='x', pady=5)

    def register_user_interface(self):
        self.new_window = tk.Toplevel(self.master)
        self.new_window.title("Registar Novo Utilizador")

        self.label_username = ttk.Label(self.new_window, text="Nome do utilizador:")
        self.label_username.pack(padx=5, pady=5)

        self.entry_username = ttk.Entry(self.new_window)
        self.entry_username.pack(padx=5, pady=5)

        self.label_password = ttk.Label(self.new_window, text="Password:")
        self.label_password.pack(padx=5, pady=5)

        self.entry_password = ttk.Entry(self.new_window, show='*')
        self.entry_password.pack(padx=5, pady=5)

        self.label_role = ttk.Label(self.new_window, text="Papel:")
        self.label_role.pack(padx=5, pady=5)

        self.entry_role = ttk.Entry(self.new_window)
        self.entry_role.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Registar", command=self.register_user)
        self.submit_button.pack(padx=5, pady=5)

    def register_user(self):
        username = self.entry_username.get()
        password = self.entry_password.get()
        role = self.entry_role.get()

        if username and password and role:
            response = Database.create_user(username, password, role)
            if response.get('success'):
                messagebox.showinfo("Sucesso", "Utilizador registado com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.get('message', 'Erro ao registar utilizador.'))
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
        current_user = 1  # ID do utilizador atual (admin)
        list_user_Commission = [1, 2]  # IDs de exemplo dos membros da comissão
        list_candidates = ["Candidato1", "Candidato2"]  # Nomes de exemplo dos candidatos
        start_date = "01-01-2023"  # Data de início de exemplo
        end_date = "01-01-2024"  # Data de fim de exemplo

        if commission_name:
            response = Database.create_election(current_user, list_user_Commission, list_candidates, commission_name, start_date, end_date)
            if response.get('success'):
                messagebox.showinfo("Sucesso", "Comissão criada com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.get('message', 'Erro ao criar comissão.'))
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")

    def create_election_interface(self):
        self.new_window = tk.Toplevel(self.master)
        self.new_window.title("Criar Eleição")

        self.label_election_name = ttk.Label(self.new_window, text="Nome da Eleição:")
        self.label_election_name.pack(padx=5, pady=5)

        self.entry_election_name = ttk.Entry(self.new_window)
        self.entry_election_name.pack(padx=5, pady=5)

        self.label_list_user_commission = ttk.Label(self.new_window, text="Membros da Comissão (IDs separados por vírgula):")
        self.label_list_user_commission.pack(padx=5, pady=5)

        self.entry_list_user_commission = ttk.Entry(self.new_window)
        self.entry_list_user_commission.pack(padx=5, pady=5)

        self.label_list_candidates = ttk.Label(self.new_window, text="Candidatos (nomes separados por vírgula):")
        self.label_list_candidates.pack(padx=5, pady=5)

        self.entry_list_candidates = ttk.Entry(self.new_window)
        self.entry_list_candidates.pack(padx=5, pady=5)

        self.label_start_date = ttk.Label(self.new_window, text="Data de Início (DD-MM-YYYY):")
        self.label_start_date.pack(padx=5, pady=5)

        self.entry_start_date = ttk.Entry(self.new_window)
        self.entry_start_date.pack(padx=5, pady=5)

        self.label_end_date = ttk.Label(self.new_window, text="Data de Fim (DD-MM-YYYY):")
        self.label_end_date.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Criar", command=self.create_election)
        self.submit_button.pack(padx=5, pady=5)

    def create_election(self):
        election_name = self.entry_election_name.get()
        current_user = 1  # ID do utilizador atual (admin)
        list_user_commission = self.entry_list_user_commission.get().split(',')
        list_candidates = self.entry_list_candidates.get().split(',')
        start_date = self.entry_start_date.get()
        end_date = self.entry_end_date.get()

        if election_name and list_user_commission and list_candidates and start_date and end_date:
            response = Database.create_election(current_user, list_user_commission, list_candidates, election_name, start_date, end_date)
            if response.get('success'):
                messagebox.showinfo("Sucesso", "Eleição criada com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.get('message', 'Erro ao criar eleição.'))
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")

def start_admin_dashboard():
    root = tk.Tk()
    app = AdminDashboard(root)
    root.mainloop()

if __name__ == "__main__":
    start_admin_dashboard()
    self.entry_end_date = ttk.Entry(self.new_window)
    self.entry_end_date.pack(padx=5, pady=5)

