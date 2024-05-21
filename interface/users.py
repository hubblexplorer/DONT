import tkinter as tk
from tkinter import messagebox

class AdminInterface(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Admin Interface")
        self.geometry("600x400")

        tk.Label(self, text="Bem-vindo à Interface de Admin", font=("Helvetica", 16)).pack(pady=20)

        self.register_user_button = tk.Button(self, text="Registrar Novo Usuário", command=self.register_user)
        self.register_user_button.pack(pady=10)

        self.register_voter_button = tk.Button(self, text="Registrar Novo Eleitor", command=self.register_voter)
        self.register_voter_button.pack(pady=10)

        self.setup_voting_button = tk.Button(self, text="Criar Votação", command=self.setup_voting)
        self.setup_voting_button.pack(pady=10)


    def register_user(self):
        # Função para registrar novos usuários
        messagebox.showinfo("Registrar Usuário", "Registrar novo usuário iniciado.")

    def register_voter(self):
        # Função para registrar novos eleitores
        messagebox.showinfo("Registrar Eleitor", "Registrar novo eleitor iniciado.")

    def setup_voting(self):
        # Função para configurar a votação
        messagebox.showinfo("Criar Votação", "Configuração da votação iniciada.")

    def authorize_voters(self):
        # Função para autorizar eleitores a votar
        messagebox.showinfo("Autorizar Eleitores", "Autorização de eleitores iniciada.")


class UserInterface(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("User Interface")
        self.geometry("600x400")

        tk.Label(self, text="Bem-vindo à Interface de Usuário", font=("Helvetica", 16)).pack(pady=20)

        self.create_commission_button = tk.Button(self, text="Iniciar Comissão Eleitoral", command=self.create_commission)
        self.create_commission_button.pack(pady=10)
        #fechar
        #contar
        
        self.verify_results_button = tk.Button(self, text="Verificar Resultados em Grupo", command=self.verify_results)
        self.verify_results_button.pack(pady=10)

    def create_commission(self):
        # Função para criar comissões eleitorais
        messagebox.showinfo("Criar Comissão", "Criação de comissão eleitoral iniciada.")

    def setup_voting(self):
        # Função para configurar votação em grupo
        messagebox.showinfo("Configurar Votação", "Configuração de votação em grupo iniciada.")

    def verify_results(self):
        # Função para verificar resultados em grupo
        messagebox.showinfo("Verificar Resultados", "Verificação de resultados em grupo iniciada.")


