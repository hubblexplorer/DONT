import hashlib
import os
import sys
import rsa
import time
# Obter o caminho do diretório pai do diretório atual
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
sys.path.append(parent_dir)
from api.api_db import Database as api

class Authenticator:
    """
    def __init__(self):
        self.usuarios = {}  # Armazenamento temporário dos usuários ativos
    """

    #Para fins logisticos, na realidade o utilizador é que tem as chaves
    def register(self, username, role):
        
        # Cria uma chave pública/privada para o novo usuário
        chave_publica, chave_privada = rsa.newkeys(512)
        print("Chave privada: ",chave_privada)
        api.create_user(current_user=1, new_pubkey=chave_publica, new_role=role, new_username=username)
        print(f"Utilizador '{nome_usuario}' registado com sucesso.")
        return True
    
    def iniciar_autenticacao(self, nome_usuario):
        # Verifica se o usuário está registrado
        if nome_usuario not in self.usuarios:
            print(f"Usuário '{nome_usuario}' não está registrado.")
            return False
        
        # Gera um novo desafio aleatório
        desafio = os.urandom(16)
        # Hash do desafio para garantir integridade
        desafio = hashlib.sha256(desafio).digest()
        return desafio
    
    def autenticar(self, nome_usuario, desafio, assinatura):
        # Verifica se o usuário está registrado
        if nome_usuario not in self.usuarios:
            print(f"Usuário '{nome_usuario}' não está registrado.")
            return False
        
        # Recupera a chave pública do usuário
        chave_publica = self.usuarios[nome_usuario]
        
        # Verifica a assinatura digital
        try:
            rsa.verify(desafio, assinatura, chave_publica)
            print(f"Usuário '{nome_usuario}' autenticado com sucesso.")
            return True
        except:
            print(f"Usuário '{nome_usuario}' falha na autenticação.")
            return False

# Exemplo de uso
if __name__ == "__main__":
    autenticador = Authenticator()

    # Registrar um novo usuário
    nome_usuario = "Manuel"
    role = "ADMIN"
    autenticador.register(nome_usuario, role)
    
    # Iniciar o processo de autenticação e obter o desafio
    desafio = autenticador.iniciar_autenticacao(nome_usuario)
    
    # Assinar o desafio com a chave privada do usuário (simulado)
    assinatura = rsa.sign(desafio, None, 'SHA-256')
    
    # Autenticar o usuário com o desafio e a assinatura
    autenticador.autenticar(nome_usuario, desafio, assinatura)
