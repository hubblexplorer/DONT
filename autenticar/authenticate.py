import hashlib
import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
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
        # Hash do desafio para exibição
        desafio = hashlib.sha256(desafio).hexdigest()
        return desafio

    @staticmethod
    def verify_signature(data, signature, public_key):
        # Carregar a chave pública
        loaded_public_key = serialization.load_pem_public_key(
            public_key.encode()
        )
        # Verificar a assinatura
        try:
            loaded_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True  # Assinatura válida
        except InvalidSignature:
            return False  # Assinatura inválida

    def autenticar(self, nome_utilizador, desafio, assinatura):
        api_instance = api()
        user_id = api_instance.get_id("users", "name", nome_utilizador).value
        # Recupera a chave pública do usuário
        chave_publica_str = api_instance.get_public_key(current_user=user_id).value

        # Verificar se 'assinatura' já está em bytes, caso contrário, converter de hexadecimal para bytes
        if isinstance(assinatura, str):
            assinatura = bytes.fromhex(assinatura)

        # Verificar se 'desafio' já está em bytes, caso contrário, converter de hexadecimal para bytes
        if isinstance(desafio, str):
            desafio = bytes.fromhex(desafio)

        # Verifica a assinatura digital 
        try:
            resultado = Authenticator.verify_signature(desafio, assinatura, chave_publica_str)
            
            if resultado:
                print(f"Utilizador '{nome_utilizador}' autenticado com sucesso.") 
                return True
            else:
                print(f"Utilizador '{nome_utilizador}' falha na autenticação.")
                return False
        except Exception as e:
            print(f"Erro ao verificar a assinatura para o utilizador '{nome_utilizador}'. ", e)
            return False
        



    
