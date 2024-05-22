# listar as eleicoes da base de dados
# Ao selecionar um, pedir as chaves privadas de cada participante da comissao
# as chaves tem de estar na pasta, ou tem de ser carregadas para o cache
# e depois faz a logica para decrypt e depois inicia entao a votaçao
# era interessante mostrar um cronómetro

import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import time
import threading
import os
import sys

# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)

from api.api_db import Database as api
from shamir import Shamir

class ShamirInterface(tk.Toplevel):
    def __init__(self, master, action, user_id):
        super().__init__(master)
        self.title(f"{action} - Shamir's Secret Sharing")
        self.geometry("600x400")
        self.master = master
        self.user_id = user_id  # Pegue o usuário autenticado do master
        self.action = action

        tk.Label(self, text=f"{action} - Shamir's Secret Sharing", font=("Helvetica", 16)).pack(pady=20)

        self.election_list = tk.Listbox(self)
        self.election_list.pack(pady=10)

        self.load_elections()  # Carregar as eleições do utilizador autenticado

        self.load_keys_button = tk.Button(self, text="Carregar Chaves", command=self.load_keys)
        self.load_keys_button.pack(pady=10)

        self.confirm_button = tk.Button(self, text=f"Confirmar {action}", command=self.confirm_action, state=tk.DISABLED)
        self.confirm_button.pack(pady=10)

        self.timer_label = tk.Label(self, text="00:00:00", font=("Helvetica", 14))
        self.timer_label.pack(pady=10)

        self.timer_running = False

    def load_elections(self):
        # Carregar eleições do utilizador autenticado
        elections = api.get_user_elections(self.user_id)  # Supondo que você tenha uma função para obter as eleições do usuário
        for election in elections:
            self.election_list.insert(tk.END, election['name'])

    def load_keys(self):
        # Função para carregar chaves privadas
        selected_election = self.election_list.get(tk.ACTIVE)
        if not selected_election:
            messagebox.showwarning("Aviso", "Selecione uma eleição primeiro.")
            return
        
        self.election_details = api.get_election_details(selected_election)  # Obter detalhes da eleição, incluindo o número de membros da comissão
        self.required_keys = self.election_details['num_comission_members']
        self.keys = filedialog.askopenfilenames(title=f"Selecione as {self.required_keys} chaves privadas", filetypes=(("Key files", "*.PEM"), ("All files", "*.*")))
        
        if len(self.keys) == self.required_keys:
            messagebox.showinfo("Chaves Carregadas", f"{len(self.keys)} chaves carregadas com sucesso.")
            self.confirm_button.config(state=tk.NORMAL)
        else:
            messagebox.showwarning("Aviso", f"Precisam ser carregadas exatamente {self.required_keys} chaves.")

    def confirm_action(self):
        # Função para confirmar a ação (iniciar ou fechar votação)
        selected_election = self.election_list.get(tk.ACTIVE)
        if selected_election:
            if self.verify_keys():
                if self.action == "Iniciar Votação":
                    self.start_voting()
                elif self.action == "Fechar Votação":
                    self.close_voting()
            else:
                messagebox.showerror("Erro", "Falha na verificação das chaves. Tente novamente.")

    def verify_keys(self):
        # Verificar as chaves usando Shamir's Secret Sharing
        return Shamir.reconstruct_init(self.keys)  # Supondo que você tenha uma função para verificar as chaves

    def start_voting(self):
        # Lógica para iniciar a votação
        messagebox.showinfo("Iniciar Votação", "Votação iniciada com sucesso.")
        self.start_timer()

    def close_voting(self):
        # Lógica para fechar a votação
        messagebox.showinfo("Fechar Votação", "Votação fechada com sucesso.")
        self.stop_timer()

    def start_timer(self):
        self.timer_running = True
        self.start_time = time.time()
        self.update_timer()

    def stop_timer(self):
        self.timer_running = False

    def update_timer(self):
        if self.timer_running:
            elapsed_time = time.time() - self.start_time
            formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
            self.timer_label.config(text=formatted_time)
            self.after(1000, self.update_timer)