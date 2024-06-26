# listar as eleicoes da base de dados
# Ao selecionar um, pedir as chaves privadas de cada participante da comissao
# as chaves tem de estar na pasta, ou tem de ser carregadas para o cache
# e depois faz a logica para decrypt e depois inicia entao a votaçao

import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import time
import threading
import os
import sys
import base64

# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)

from api.api_db import Database as api
from shamir import Shamir
from sistema.voting_system import VotingSystem
from resources.rsa_sign.keys_rsa import encrypt_message, decrypt_message

class ShamirInterface(tk.Toplevel):
    def __init__(self, master, action, user_id):
        super().__init__(master)
        self.title(f"{action} - Shamir's Secret Sharing")
        self.geometry("600x400")
        self.master = master
        self.user_id = user_id  # Pegue o usuário autenticado do master
        self.action = action
        self.api_instance = api()
        self.success = False  # Atributo para armazenar o resultado da verificação

        tk.Label(self, text=f"{action} - Shamir's Secret Sharing", font=("Helvetica", 16)).pack(pady=20)

        self.election_tree = ttk.Treeview(self, columns=('ID', 'Nome'), show='headings')
        self.election_tree.heading('ID', text='ID')
        self.election_tree.heading('Nome', text='Nome')
        self.election_tree.pack(pady=10, fill=tk.BOTH, expand=True)

        self.load_elections()  # Carregar as eleições do utilizador autenticado

        self.load_keys_button = tk.Button(self, text="Carregar Chaves", command=self.load_keys)
        self.load_keys_button.pack(pady=10)

        self.confirm_button = tk.Button(self, text=f"Confirmar {action}", command=self.confirm_action, state=tk.DISABLED)
        self.confirm_button.pack(pady=10)

    def load_elections(self):
        # Carregar eleições do utilizador autenticado
        elections = self.api_instance.get_elections_by_user(current_user=self.user_id)
        for election in elections.value:
            self.election_tree.insert('', tk.END, values=(election[0], election[1]), tags=(election[5],))

    def load_keys(self):
        # Função para carregar chaves privadas
        selected_item = self.election_tree.selection()
        if not selected_item:
            messagebox.showwarning("Aviso", "Selecione uma eleição primeiro.")
            return
        
        self.selected_election_id = self.election_tree.item(selected_item)['values'][0]
        self.selected_election_comission = self.election_tree.item(selected_item, 'tags')[0]

        self.commission_details = self.api_instance.get_commission_members(current_user=self.user_id, Commission_id=self.selected_election_comission)  # Obter detalhes da eleição, incluindo o número de membros da comissão
        self.required_keys = len(self.commission_details.value)
        self.keys = filedialog.askopenfilenames(title=f"Selecione as {self.required_keys} chaves privadas", filetypes=(("Key files", "*.PEM"), ("All files", "*.*")))
        
        if len(self.keys) == self.required_keys:
            messagebox.showinfo("Chaves Carregadas", f"{len(self.keys)} chaves carregadas com sucesso.")
            self.confirm_button.config(state=tk.NORMAL)
            print(self.keys)
        else:
            messagebox.showwarning("Aviso", f"Precisam ser carregadas exatamente {self.required_keys} chaves.")

    def confirm_action(self):
        # Função para confirmar a ação (iniciar ou fechar votação)
        selected_item = self.election_tree.selection()
        if selected_item:
            if self.verify_keys():
                if self.action == "Iniciar Votação":
                    self.start_voting()
                elif self.action == "Fechar Votação":
                    self.close_voting()
                elif self.action == "Verificar Resultados":
                    self.verify_results()
                elif self.action == "Votar":
                    self.open_voting_app()
            else:
                messagebox.showerror("Erro", "Falha na verificação das chaves. Tente novamente.")
    
    def open_voting_app(self):
        return True

    def verify_keys(self):
        # Verificar as chaves usando Shamir's Secret Sharing
        try:
            keys_parts = []
            for i, member in enumerate(self.commission_details.value):
                key = member[2]
                with open(self.keys[i], 'r') as file:
                    private_key = file.read()
                decrypted_key, prime = decrypt_message(private_key, key).split('|DIV|')
                x, y = map(int, decrypted_key.strip('()').split(','))
                keys_parts.append((x, y))
            
            # Reconstruir o segredo usando Shamir's Secret Sharing
            shamir = Shamir(keys_parts, int(prime))
            secret = shamir.secret
            
            # Verifique se o segredo foi reconstruído corretamente
            if secret:
                self.segredo = secret
                self.success = True
                return True
            else:
                self.success = False
                return False
        except Exception as e:
            print(f"Erro ao verificar as chaves: {e}")
            self.success = False
            return False

    def start_voting(self):
        # Lógica para iniciar a votação
        iniciar = self.api_instance.change_election_active_status(current_user=int(self.user_id), Id_election=int(self.selected_election_id), status=True)
        if iniciar:
            messagebox.showinfo("Iniciar Votação", "Votação iniciada com sucesso.")
            self.success = True
            self.destroy()  # Fechar a janela atual após iniciar a votação
        else:
            messagebox.showerror("Erro", "Não foi possível iniciar a votação.")

    def close_voting(self):
        # Lógica para fechar a votação
        fechar = self.api_instance.change_election_active_status(current_user=self.user_id, Id_election=self.selected_election_id, status=False)
        if fechar:
            messagebox.showinfo("Fechar Votação", "Votação fechada com sucesso.")
            self.success = True
            self.destroy()  # Fechar a janela atual após fechar a votação
        else:
            messagebox.showerror("Erro", "Não foi possível fechar a votação.")

    def verify_results(self):
        # Lógica para verificar os resultados
        try:
            result = self.count_votes(self.user_id, self.selected_election_id)
            if result:
                self.show_results(result)
            else:
                messagebox.showinfo("Resultados", "Não há votos registrados para esta eleição.")
            self.success = True
            self.destroy()  # Fechar a janela atual após verificar os resultados
        except Exception as e:
            print(f"Erro ao verificar os resultados: {e}")
            self.success = False

    def show_results(self, result):
        # Cria uma nova janela para mostrar os resultados
        results_window = tk.Toplevel(self)
        results_window.title("Resultados da Eleição")
        
        # Cria uma tabela para exibir os resultados
        table = ttk.Treeview(results_window, columns=('Partido', 'Votos'), show='headings')
        table.heading('Partido', text='Partido')
        table.heading('Votos', text='Votos')

        # Preenche a tabela com os resultados
        for partido, votos in result:
            table.insert('', tk.END, values=(partido, votos))

        table.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)


    def count_votes(self, current_user, Id_election):
        voting_system = VotingSystem(self.api_instance)

        """Conta os votos válidos para cada partido e ordena por ordem de mais votos."""
        result = self.api_instance.get_votes(current_user, Id_election)
        if result.is_err():
            print("Erro ao obter votos:", result.message)
        else:
            votes = result.unwrap()
            # Dicionario para contar os votos por partido
            vote_counts = {}

            for vote_record in votes:
                partido = vote_record[0]  # O valor do voto representa o partido
                provided_hmac = vote_record[1]  # O HMAC fornecido
                key_str = vote_record[2]  # A chave de integridade armazenada
                try:
                    key = voting_system.decrypt_key(key_str, self.segredo)  # Decrypt key should take the base64 encoded string
                    print("CHAVE DECIFARDA: ",key)
                except ValueError as e:
                    print(f"Erro ao converter chave de integridade para bytes: {e}")
                    continue  # Pula este registro de voto

                partido = voting_system.decrypt_vote(partido, key)
                print("PARTIDO: ",partido)

                # Ensure partido is bytes for HMAC verification
                partido_bytes = partido.encode()

                type(provided_hmac)
                # Verifica a integridade do voto
                if voting_system.verify_hmac(partido,key,str(provided_hmac)):
                    #partido = partido.decode('utf-8')
                    # Decode partido back to string for counting
                    if partido in vote_counts:
                        vote_counts[partido] += 1
                    else:
                        vote_counts[partido] = 1

            # Ordena os partidos por numero de votos em ordem decrescente
            sorted_vote_counts = sorted(vote_counts.items(), key=lambda item: item[1], reverse=True)

            print("Contagem de votos por partido (ordenada):", sorted_vote_counts)
            return sorted_vote_counts