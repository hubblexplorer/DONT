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
    
    #Para fins logisticos, na realidade o utilizador é que tem as chaves
    def register(self, username, role, current_user):
        
        # Cria uma chave pública/privada para o novo usuário
        self.chave_publica, chave_privada = rsa.newkeys(512)
        print("Chave privada: ",chave_privada)
        #api.create_user(current_user=current_user, new_pubkey=chave_publica, new_role=role, new_username=username)
        print(f"Utilizador '{nome_usuario}' registado com sucesso.")
        return self.chave_publica, chave_privada
    """
    def iniciar_autenticacao(self, nome):
        # Gera um novo desafio aleatório
        desafio = os.urandom(16)
        # Hash do desafio para garantir integridade
        desafio = hashlib.sha256(desafio).digest()

        return desafio
    
    def autenticar(self, nome_utilizador, desafio, assinatura):
        api_instance = api()
        # Recupera a chave pública do usuário
        chave_publica = api_instance.pubkey(username=nome_utilizador, n_contribuinte=123123123)

        # Verifica a assinatura digital 
        try:
            rsa.verify(desafio, assinatura, chave_publica)
            print(f"Usuário '{nome_utilizador}' autenticado com sucesso.") 
            return True
        except:
            print(f"Usuário '{nome_utilizador}' falha na autenticação.")
            return False

# Exemplo de uso
if __name__ == "__main__":
    autenticador = Authenticator()

    # Registrar um novo usuário
    nome_usuario = "Manuel"
    role = "ADMIN"
    current_user = 1
    
    pubkey, privkey = autenticador.register(nome_usuario, role, current_user)
    
    # Iniciar o processo de autenticação e obter o desafio
    desafio = autenticador.iniciar_autenticacao(nome_usuario)
    
    # Assinar o desafio com a chave privada do usuário (simulado)
    assinatura = rsa.sign(desafio, privkey, 'SHA-256')
    
    # Autenticar o usuário com o desafio e a assinatura
    autenticador.autenticar(nome_usuario, desafio, assinatura)
