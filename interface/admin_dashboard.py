import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
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

class AdminDashboard(tk.Toplevel):
    def __init__(self, master, id_user):
        super().__init__(master)
        self.title("Admin Dashboard")
        self.geometry("600x400")
        self.id_user = id_user

        #self.create_widgets()
        #self.frame = tk.Frame(self.master)
        #self.frame.pack(padx=10, pady=10, fill='x', expand=True)

        # Botão para registar novo utilizador
        self.register_user_button = tk.Button(self, text="Registar Novo Utilizador", command=self.register_user_interface)
        self.register_user_button.pack(fill='x', pady=5)

        # Botão para criar comissão
        #self.create_commission_button = tk.Button(self.frame, text="Criar Comissão", command=self.create_commission_interface)
        #self.create_commission_button.pack(fill='x', pady=5)

        # Botão para criar eleição
        self.create_election_button = tk.Button(self, text="Criar Eleição", command=self.create_election_interface)
        self.create_election_button.pack(fill='x', pady=5)


        self.create_candidate_button = tk.Button(self, text="Criar Candidato", command=self.create_candidate_interface)
        self.create_candidate_button.pack(fill='x', pady=5)

        self.check_logs = tk.Button(self, text="Ver Logs", command=self.check_logs_interface)
        self.check_logs.pack(fill='x', pady=5)
    

    def check_logs_interface(self):
        self.new_window = tk.Toplevel(self)
        self.new_window.title("Ver Logs")

        db = Database()
        logs = db.get_logs(self.id_user).unwrap()
        db.conn.close()

        tree = ttk.Treeview(self.new_window, columns=("id", "TimeStamp", "Id_user", "Action", "Details"), show="headings")

        tree.heading("id", text="ID")
        tree.heading("TimeStamp", text="TimeStamp")
        tree.heading("Id_user", text="Id_user")
        tree.heading("Action", text="Action")
        tree.heading("Details", text="Details")



        for log in logs:
            tree.insert("", "end", values=log)

        tree.pack(expand=True, fill=tk.BOTH)








      

    def create_candidate_interface(self):
        self.candidate_name = tk.StringVar()
       

        self.new_window = tk.Toplevel(self)
        self.new_window.title("Criar Candidato")


        self.label_name = ttk.Label(self.new_window, text="Nome do Candidato:")
        self.label_name.pack(padx=5, pady=5)

        self.entry_name = ttk.Entry(self.new_window, textvariable=self.candidate_name)
        self.entry_name.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Registar", command=self.register_candidate)
        self.submit_button.pack(padx=5, pady=5)

    def register_candidate(self):
        name = self.candidate_name.get()

        db = Database()

        if name:
            response = db.add_candidate(self.id_user, name)
            if response.is_ok():
                messagebox.showinfo("Sucesso", "Candidato registado com sucesso!")
            else:
                messagebox.showerror("Erro", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")
        db.conn.close()



    def register_user_interface(self):
        self.new_username = tk.StringVar(self)
        self.new_role =  tk.StringVar(self)
        self.new_role.set("ADMIN") # default value

        self.new_window = tk.Toplevel(self)
        self.new_window.title("Registar Novo Utilizador")

        self.label_username = ttk.Label(self.new_window, text="Nome do utilizador:")
        self.label_username.pack(padx=5, pady=5)

        self.entry_username = ttk.Entry(self.new_window, textvariable=self.new_username)
        self.entry_username.pack(padx=5, pady=5)

        self.label_role = ttk.Label(self.new_window, text="Papel:")
        self.label_role.pack(padx=5, pady=5)

        self.entry_role = ttk.OptionMenu(self.new_window, self.new_role, "ADMIN", "USER", "VOTER")
        self.entry_role.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Registar", command=self.register_user)
        self.submit_button.pack(padx=5, pady=5)

    def register_user(self):
        username = self.new_username.get()
        private, public = generate_rsa_keypair()
        role = self.new_role.get()

        db = Database()
        
        if username and private and role:
            response = db.create_user(self.id_user, username, private, role)
            file = open(f"keys/{username}.pem", "w")
            file.write(public)
            file.close()
            if response.is_ok():
                messagebox.showinfo("Sucesso", "Utilizador registado com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")
        db.conn.close()

    """
    def create_commission_interface(self):
        self.new_window = ttk.Toplevel(self.master)
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
    """
    def create_election_interface(self):

        self.election_name = tk.StringVar()
        self.start_date = tk.StringVar()
        self.end_date = tk.StringVar()

        self.selected_users = tk.Listbox()
        self.selected_candidates = tk.Listbox()

        db = Database()
        
        self.list_users = db.get_user_by_role("USER").unwrap()


        self.list_candidates = db.get_candidates().unwrap()

        db.conn.close()


        self.new_window = tk.Toplevel(self)
        self.new_window.title("Criar Eleição")

        self.label_election_name = ttk.Label(self.new_window, text="Nome da Eleição:")
        self.label_election_name.pack(padx=5, pady=5)

        self.entry_election_name = ttk.Entry(self.new_window, textvariable=self.election_name)
        self.entry_election_name.pack(padx=5, pady=5)

        self.label_list_user_commission = ttk.Label(self.new_window, text="Membros da Comissão (selecione pelo menos 3) :")
        self.listbox_user_commission = tk.Listbox(self.new_window, listvariable=self.selected_users, selectmode=tk.MULTIPLE, exportselection=0)
        for user in self.list_users:
            self.listbox_user_commission.insert(tk.END, user)
        self.listbox_user_commission.pack(padx=5, pady=5)

        self.label_list_candidates = ttk.Label(self.new_window, text="Candidatos (selecione pelo menos 2):").pack(padx=5, pady=5)
        self.listbox_candidates = tk.Listbox(self.new_window, listvariable=self.selected_candidates, selectmode=tk.MULTIPLE, exportselection=0)
        for candidate in self.list_candidates:
            self.listbox_candidates.insert(tk.END, candidate)
        self.listbox_candidates.pack(padx=5, pady=5)

        self.label_start_date = ttk.Label(self.new_window, text="Data de Início (DD-MM-YYYY):")
        self.label_start_date.pack(padx=5, pady=5)

        self.entry_start_date = ttk.Entry(self.new_window)
        self.entry_start_date.pack(padx=5, pady=5)

        self.label_end_date = ttk.Label(self.new_window, text="Data de Fim (DD-MM-YYYY):")
        self.label_end_date.pack(padx=5, pady=5)

        self.entry_end_date = ttk.Entry(self.new_window)
        self.entry_end_date.pack(padx=5, pady=5)

        self.submit_button = ttk.Button(self.new_window, text="Criar", command=self.create_election)
        self.submit_button.pack(padx=5, pady=5)

    def create_election(self):
        election_name = self.entry_election_name.get()
        list_user_commission = self.listbox_user_commission.curselection()
        list_candidates = self.listbox_candidates.curselection()
        start_date = self.entry_start_date.get()
        end_date = self.entry_end_date.get()


        aux = []
        for i in list_user_commission:
            aux.append(self.list_users[i][0])
        list_user_commission = aux

        aux = []
        for i in list_candidates:
            aux.append(self.list_candidates[i][0])
        list_candidates = aux

        db = Database()
        
        if election_name and list_user_commission and list_candidates and start_date and end_date:
            response = db.create_election(self.id_user, list_user_commission, list_candidates, election_name, start_date, end_date)
            if response.is_ok():
                messagebox.showinfo("Sucesso", "Eleição criada com sucesso!")
                self.new_window.destroy()
            else:
                messagebox.showerror("Erro: ", response.message)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, preencha todos os campos.")
        db.conn.close()


#def start_admin_dashboard():
#    root = tk.Tk()
#    app = AdminDashboard(root)
#    root.mainloop()

#if __name__ == "__main__":
#    start_admin_dashboard()
#    self.entry_end_date = tk.Entry(self.new_window)
#    self.entry_end_date.pack(padx=5, pady=5)

