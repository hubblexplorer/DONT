import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import pyperclip
import os
import sys

# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)

from autenticar.authenticate import Authenticator

class SignatureAuthenticationApp:
    def __init__(self, master):
        self.master = master
        master.title("Autenticação por Assinatura Digital")
        
        self.authenticator = Authenticator()
        self.nome_var = tk.StringVar()
        self.desafio = ""  # Variável de instância para armazenar o hash do desafio
        self.result = None
        self.nome_utilizador = None

        self.create_widgets()
        self.return_to_initial()

    def create_widgets(self):
        self.label_nome = ttk.Label(self.master, text="Digite seu nome:")
        self.label_nome.pack(padx=5, pady=5)

        self.nome_entry = ttk.Entry(self.master, textvariable=self.nome_var)
        self.nome_entry.pack(padx=5, pady=5)

        self.next_button = ttk.Button(self.master, text="Seguinte", command=self.next_interface)
        self.next_button.pack(padx=5, pady=5)

        self.desafio_label = ttk.Label(self.master, text="")
        self.copy_button = ttk.Button(self.master, text="Copiar Desafio", command=self.copy_challenge)
        self.copy_button.pack(padx=5, pady=5)

        self.assinatura_text = tk.Text(self.master, height=5, width=30)
        self.assinatura_text.pack(padx=5, pady=5)

        self.authenticate_button = ttk.Button(self.master, text="Autenticar", command=self.authenticate)
        self.authenticate_button.pack(padx=5, pady=5)

        self.return_button = ttk.Button(self.master, text="Voltar", command=self.return_to_initial)
        self.return_button.pack(padx=5, pady=5)

    def next_interface(self):
        self.nome_utilizador = self.nome_var.get().strip()
        if self.nome_utilizador:
            self.desafio = self.authenticator.iniciar_autenticacao(self.nome_utilizador)
            self.desafio_label.config(text=f"{self.nome_utilizador}, assine o desafio: {self.desafio}")
            self.toggle_widgets(False)
        else:
            messagebox.showwarning("Entrada Inválida", "Por favor, digite seu nome antes de prosseguir.")

    def return_to_initial(self):
        self.master.title("Autenticação por Assinatura Digital")
        self.nome_var.set("")
        self.desafio = b""
        self.desafio_hash = ""
        self.desafio_label.config(text="")
        self.assinatura_text.delete("1.0", tk.END)
        self.toggle_widgets(True)

    def toggle_widgets(self, initial):
        if initial:
            self.label_nome.pack()
            self.nome_entry.pack()
            self.next_button.pack()
            self.desafio_label.pack_forget()
            self.copy_button.pack_forget()
            self.assinatura_text.pack_forget()
            self.authenticate_button.pack_forget()
            self.return_button.pack_forget()
        else:
            self.label_nome.pack_forget()
            self.nome_entry.pack_forget()
            self.next_button.pack_forget()
            self.desafio_label.pack()
            self.copy_button.pack()
            self.assinatura_text.pack()
            self.authenticate_button.pack()
            self.return_button.pack()

    def copy_challenge(self):
        pyperclip.copy(self.desafio)
        messagebox.showinfo("Copiar Desafio", "Desafio copiado para a área de transferência.")

    def authenticate(self):
        nome_utilizador = self.nome_var.get().strip()
        assinatura = self.assinatura_text.get("1.0", "end-1c")

        if self.authenticator.autenticar(nome_utilizador, self.desafio, assinatura):
            messagebox.showinfo("Autenticação", "Autenticação bem sucedida!")
            self.result = True
            self.master.destroy()  # Fechar a janela de autenticação atual
        else:
            messagebox.showerror("Autenticação", "Autenticação falhou.")
            self.result = False
