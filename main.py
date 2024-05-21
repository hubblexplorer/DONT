import tkinter as tk
from tkinter import messagebox
from interface.autenticacao import SignatureAuthenticationApp
from api.api_db import Database as api
from interface.users import UserInterface, AdminInterface
from interface.VotingApp import VotingApp

class VotingSystemApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sistema de Votação Eletrônica")
        self.geometry("600x400")

        self.label = tk.Label(self, text="Bem-vindo ao Sistema de Votação Eletrônica", font=("Helvetica", 16))
        self.label.pack(pady=20)

        self.auth_button = tk.Button(self, text="Autenticar", command=self.authenticate_user, font=("Helvetica", 14))
        self.auth_button.pack(pady=20)

        self.authenticated = False  # Flag para verificar se o usuário está autenticado

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
            user_id = api_instance.get_id("users", "name", user).value
            user_role = api_instance.get_role(user_id).value


            if user_role == "ADMIN":
                self.show_admin_interface()
            elif user_role == "USER":
                self.show_user_interface()
            else:
                self.show_voter_interface()

    def show_admin_interface(self):
        admin_interface = AdminInterface(self)
        admin_interface.grab_set()

    def show_user_interface(self):
        user_interface = UserInterface(self)
        user_interface.grab_set()

    def show_voter_interface(self):
        voter_window = tk.Toplevel(self)
        voter_app = VotingApp(voter_window) 
        # Torna a janela modal
        voter_window.transient(self)
        voter_window.grab_set()
        self.wait_window(voter_window)

if __name__ == "__main__":
    app = VotingSystemApp()
    app.mainloop()

