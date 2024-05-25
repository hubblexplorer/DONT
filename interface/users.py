import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from shamir_interface import ShamirInterface
from main import VotingSystemApp

class UserInterface(tk.Toplevel):
    def __init__(self, master, user_id):
        super().__init__(master)
        self.master = master
        self.title("User Interface")
        self.geometry("600x400")
        self.user_id = user_id

        tk.Label(self, text="Bem-vindo à Interface de Utilizador", font=("Helvetica", 16)).pack(pady=20)

        self.init_button = tk.Button(self, text="Iniciar Eleição", command=self.init_eleicao)
        self.init_button.pack(pady=10)

        self.close_button = tk.Button(self, text="Fechar Eleição", command=self.close_results)
        self.close_button.pack(pady=10)

        self.verify_results_button = tk.Button(self, text="Verificar Resultados", command=self.verify_results)
        self.verify_results_button.pack(pady=10)

        self.vote_button = tk.Button(self, text="Votar", command=self.votar)
        self.vote_button.pack(pady=10)

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

    def votar(self):
        shamir_interface = ShamirInterface(self, "Votar", self.user_id)
        shamir_interface.grab_set()

        self.withdraw()  # Esconde a janela atual sem destruir

        self.wait_window(shamir_interface)
        secret = shamir_interface.segredo
        if shamir_interface.success:
            # Fechar todas as janelas abertas e a janela principal
            self.destroy()  # Destroi a janela atual de UserInterface
            self.master.destroy()  # Destroi a janela principal (VotingSystemApp)

            # Criar uma nova instância de VotingSystemApp
            new_app = VotingSystemApp(secret)
            # Iniciar o loop principal da nova instância
            new_app.mainloop()
        else:
            # Mostra a janela principal novamente em caso de falha
            self.deiconify()
            messagebox.showerror("Erro", "Falha na verificação das chaves. Tente novamente.")
            