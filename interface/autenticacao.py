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

        self.create_widgets()
        self.return_to_initial()

    def create_widgets(self):
        self.label_nome = ttk.Label(self.master, text="Digite seu nome:")
        self.label_nome.grid(row=0, column=0, padx=5, pady=5)

        self.nome_entry = ttk.Entry(self.master, textvariable=self.nome_var)
        self.nome_entry.grid(row=0, column=1, padx=5, pady=5)

        self.next_button = ttk.Button(self.master, text="Seguinte", command=self.next_interface)
        self.next_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        self.desafio_label = ttk.Label(self.master, text="")
        self.desafio_label.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        self.copy_button = ttk.Button(self.master, text="Copiar Desafio", command=self.copy_challenge)
        self.copy_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.assinatura_text = tk.Text(self.master, height=5, width=30)
        self.assinatura_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        self.authenticate_button = ttk.Button(self.master, text="Autenticar", command=self.authenticate)
        self.authenticate_button.grid(row=5, column=0, padx=5, pady=5)

        self.return_button = ttk.Button(self.master, text="Voltar", command=self.return_to_initial)
        self.return_button.grid(row=5, column=1, padx=5, pady=5)

    def next_interface(self):
        nome_utilizador = self.nome_var.get().strip()
        if nome_utilizador:
            self.desafio = self.authenticator.iniciar_autenticacao(nome_utilizador)
            self.desafio_label.config(text=f"{nome_utilizador}, assine o desafio: {self.desafio}")
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
        self.label_nome.grid(row=0, column=0, padx=5, pady=5) if initial else self.label_nome.grid_forget()
        self.nome_entry.grid(row=0, column=1, padx=5, pady=5) if initial else self.nome_entry.grid_forget()
        self.next_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5) if initial else self.next_button.grid_forget()

        if not initial:
            self.desafio_label.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
            self.copy_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
            self.assinatura_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
            self.authenticate_button.grid(row=3, column=0, padx=5, pady=5)
            self.return_button.grid(row=3, column=1, padx=5, pady=5)
        else:
            self.desafio_label.grid_forget()
            self.copy_button.grid_forget()
            self.assinatura_text.grid_forget()
            self.authenticate_button.grid_forget()
            self.return_button.grid_forget()

    def copy_challenge(self):
        pyperclip.copy(self.desafio)
        messagebox.showinfo("Copiar Desafio", "Desafio copiado para a área de transferência.")

    def authenticate(self):
        nome_utilizador = self.nome_var.get().strip()
        assinatura = self.assinatura_text.get("1.0", "end-1c")

        if self.authenticator.autenticar(nome_utilizador, self.desafio, assinatura):
            messagebox.showinfo("Autenticação", "Autenticação bem sucedida!")
        else:
            messagebox.showerror("Autenticação", "Autenticação falhou.")

def main():
    root = tk.Tk()
    app = SignatureAuthenticationApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()