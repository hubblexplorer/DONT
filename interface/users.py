import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from shamir_interface import ShamirInterface

# Importar a classe AdminDashboard do novo arquivo
from .admin_dashboard import AdminDashboard

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
    def __init__(self, master, user_id):
        super().__init__(master)
        self.title("User Interface")
        self.geometry("600x400")
        self.user_id = user_id

        tk.Label(self, text="Bem-vindo à Interface de Usuário", font=("Helvetica", 16)).pack(pady=20)

        self.init_button = tk.Button(self, text="Iniciar Eleição", command=self.init_eleicao)
        self.init_button.pack(pady=10)

        self.close_button = tk.Button(self, text="Fechar Eleição", command=self.close_results)
        self.close_button.pack(pady=10)

        self.verify_results_button = tk.Button(self, text="Verificar Resultados", command=self.verify_results)
        self.verify_results_button.pack(pady=10)

    def init_eleicao(self):
        # Abre a interface de Shamir para iniciar a eleição
        shamir_interface = ShamirInterface(self, "Iniciar Votação", self.user_id)
        shamir_interface.grab_set()

    def close_results(self):
        # Abre a interface de Shamir para verificar resultados
        shamir_interface = ShamirInterface(self, "Fechar Votação", self.user_id)
        shamir_interface.grab_set()

    def verify_results(self):
        shamir_interface = ShamirInterface(self, "Verificar Resultados", self.user_id)
        shamir_interface.grab_set()



if __name__ == "__main__":
    root = tk.Tk()
    root.title("Interface Principal")

    def open_admin_dashboard():
        new_window = tk.Toplevel(root)
        app = AdminDashboard(new_window)

    main_frame = ttk.Frame(root)
    main_frame.pack(padx=10, pady=10, fill='x', expand=True)

    admin_button = ttk.Button(main_frame, text="Abrir Dashboard de Admin", command=open_admin_dashboard)
    admin_button.pack(fill='x', pady=5)

    root.mainloop()
