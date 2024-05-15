import tkinter as tk
from tkinter import ttk
import tkinter.filedialog as filedialog
import pyperclip

import os
import rsa
import sys
# Obter o caminho do diretório pai do diretório atual
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
sys.path.append(parent_dir)
#from api.api_db import Database
from autenticar.authenticate import Authenticator




class SignatureAuthenticationApp:
    def __init__(self, master):
        self.master = master
        master.title("Autenticação por Assinatura Digital")

        self.authenticator = Authenticator()

        self.nome_var = tk.StringVar()

        self.label_nome = ttk.Label(master, text="Digite seu nome:")
        self.label_nome.grid(row=0, column=0, padx=5, pady=5)

        self.nome_entry = ttk.Entry(master, textvariable=self.nome_var)
        self.nome_entry.grid(row=0, column=1, padx=5, pady=5)

        self.next_button = ttk.Button(master, text="Seguinte", command=self.next_interface)
        self.next_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.desafio_label = ttk.Label(master, text="")
        self.desafio_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.copy_button = ttk.Button(master, text="Copiar Desafio", command=self.copy_challenge)
        self.copy_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.assinatura_text = tk.Text(master, height=5, width=30)
        self.assinatura_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        self.authenticate_button = ttk.Button(master, text="Autenticar", command=self.authenticate)
        self.authenticate_button.grid(row=5, column=0, padx=5, pady=5)

        self.return_button = ttk.Button(master, text="Voltar", command=self.return_to_initial)
        self.return_button.grid(row=5, column=1, padx=5, pady=5)

        self.return_to_initial()

    def next_interface(self):
        nome_utilizador = self.nome_var.get().strip()
        if nome_utilizador:
            desafio = self.authenticator.iniciar_autenticacao(nome_utilizador)
            self.desafio_label.config(text=f"{nome_utilizador}, assine o desafio: {desafio}")
            self.label_nome.grid_forget()
            self.nome_entry.grid_forget()
            self.next_button.grid_forget()
            self.desafio_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
            self.copy_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
            self.assinatura_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
            self.authenticate_button.grid(row=3, column=0, padx=5, pady=5)
            self.return_button.grid(row=3, column=1, padx=5, pady=5)
        else:
            print("Por favor, digite seu nome antes de prosseguir.")

    def return_to_initial(self):
        self.master.title("Autenticação por Assinatura Digital")
        self.desafio_label.grid_forget()
        self.copy_button.grid_forget()
        self.assinatura_text.grid_forget()
        self.authenticate_button.grid_forget()
        self.return_button.grid_forget()
        self.label_nome.grid(row=0, column=0, padx=5, pady=5)
        self.nome_entry.grid(row=0, column=1, padx=5, pady=5)
        self.next_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

    def copy_challenge(self):
        desafio = self.desafio_label.cget("text").split(": ")[1]
        pyperclip.copy(desafio)
        print("Desafio copiado para a área de transferência.")

    def authenticate(self):
        nome_utilizador = self.nome_var.get().strip()
        desafio = self.desafio_label.cget("text").split(": ")[1].split(",")[0]
        desafio = desafio.encode()
        assinatura = self.assinatura_text.get("1.0", "end-1c").encode()

        if self.authenticator.autenticar(nome_utilizador, desafio, assinatura):
            print("Autenticação bem sucedida!")
        else:
            print("Autenticação falhou.")

def main():
    root = tk.Tk()
    app = SignatureAuthenticationApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
