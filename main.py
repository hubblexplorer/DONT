import tkinter as tk
from tkinter import messagebox
import os
import sys

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))

# Add it to the system path if it's not already there
queue = [parent_dir]

while queue:
    dir = queue.pop(0)
    for entry in os.scandir(dir):
        sys.path.append(entry.path)
        if entry.is_dir():
            queue.append(entry.path)



# Importações dos módulos necessários
from admin_dashboard import AdminDashboard
from interface.autenticacao import SignatureAuthenticationApp
from api.api_db import Database as api
from interface.users import UserInterface, AdminInterface
from sistema.voting_system import VotingSystem
from interface.VotingApp import VotingApp



class VotingSystemApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Votação Eletrónica")
        self.geometry("600x400")

        self.label = tk.Label(self, text="Bem-vindo ao Sistema de Votação Eletrónica", font=("Helvetica", 16))
        self.label.pack(pady=20)

        self.auth_button = tk.Button(self, text="Autenticar", command=self.authenticate_user, font=("Helvetica", 14))
        self.auth_button.pack(pady=20)

        self.authenticated = False  # Flag para verificar se o usuário está autenticado
        self.db = api()

    def authenticate_user(self):
        self.auth_button.config(state="disabled")  # Desabilita o botão de autenticação
        auth_window = tk.Toplevel(self)
        auth_app = SignatureAuthenticationApp(auth_window)
        
        # Torna a janela modal
        auth_window.transient(self)
        auth_window.grab_set()
        self.wait_window(auth_window)
        
        if auth_app.result:
            print(auth_app.nome_utilizador)
            self.authenticated = True
            # Fecha completamente a janela principal após a autenticação bem-sucedida
            self.withdraw() #Para esconder a janela principal sem fechar
            #messagebox.showinfo("Autenticação", "Autenticação bem-sucedida!")
            self.show_main_interface(auth_app.nome_utilizador)
        else:
            self.auth_button.config(state="normal")  # Reabilita o botão de autenticação se a autenticação falhar
            #messagebox.showerror("Autenticação", "Falha na autenticação. Tente novamente.")

    def show_main_interface(self, user):
        if self.authenticated:
            if self.auth_button.winfo_exists():  # Verifica se o botão ainda existe antes de escondê-lo
                self.auth_button.pack_forget()  # Esconde o botão de autenticação após o login bem-sucedido

            api_instance = api()
            self.user_id = api_instance.get_id("users", "name", user).value
            user_role = api_instance.get_role(self.user_id).value


            if user_role == "ADMIN":
                self.show_admin_interface()
            elif user_role == "USER":
                UserInterface(self, self.user_id)
            else:
                self.show_voter_interface()

    def show_admin_interface(self):
        admin_dashboard = AdminDashboard(self,self.user_id)
        admin_dashboard.grab_set()

    def show_user_interface(self):
        user_interface = UserInterface(self)
        user_interface.grab_set()

    def show_voter_interface(self):
        voting_window = tk.Toplevel(self)
        app = VotingApp(voting_window)
        self.wait_window(voting_window)
        vote = app.get_vote()
        election_id = self.db.get_elections_global().unwrap()
        print("Eleição: ",election_id)
        system = VotingSystem(self.db)
        system.store_vote(self.user_id,election_id,vote,"")

if __name__ == "__main__":
    app = VotingSystemApp()
    app.mainloop()