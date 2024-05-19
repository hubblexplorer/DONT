import hashlib
import hmac
import secrets
import os
import sys
import sqlite3
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

sys.path.append('interface')
from VotingApp import start_app

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)
from api.api_db import Database

DATABASE_DIR = os.path.join(parent_dir, 'resources')

class VotingSystem:
    def __init__(self):
        """Inicia a classe que gera uma nova chave de integridade para a votação."""
        self.integrity_key = secrets.token_bytes(32)  # Gera uma chave segura de 256 bits

    def derive_key(self, password, salt):
        """Deriva uma chave AES de 128 bits a partir da senha fornecida usando PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_vote(self, vote, password):
        """Cifra um voto AES128-CBC com uma chave derivada da senha fornecida."""
        salt = secrets.token_bytes(16)
        key = self.derive_key(password, salt)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        vote_bytes = vote.encode('utf-8')
        padded_vote = vote_bytes + b"\0" * (16 - len(vote_bytes) % 16)
        ciphertext = encryptor.update(padded_vote) + encryptor.finalize()
        return urlsafe_b64encode(salt + iv + ciphertext).decode('utf-8')

    def decrypt_vote(self, encrypted_vote, password):
        """Decifra um voto AES128-CBC com uma chave derivada da senha fornecida."""
        data = urlsafe_b64decode(encrypted_vote.encode('utf-8'))
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]
        key = self.derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_vote = decryptor.update(ciphertext) + decryptor.finalize()
        return padded_vote.rstrip(b"\0").decode('utf-8')

    def generate_hmac(self, vote):
        """Gera um HMAC-SHA512 para um voto usando a chave de integridade da votacao atual."""
        vote_bytes = vote.encode('utf-8')
        return hmac.new(self.integrity_key, vote_bytes, hashlib.sha512).hexdigest()

    def verify_hmac(self, vote, provided_hmac):
        """Verifica o HMAC de um voto submetido comparando com um HMAC fornecido."""
        expected_hmac = self.generate_hmac(vote)
        return hmac.compare_digest(expected_hmac, provided_hmac)

    def store_vote(self, vote, password):
        """Cifra e armazena um voto na base de dados."""
        encrypted_vote = self.encrypt_vote(vote, password)
        hmac_result = self.generate_hmac(vote)
        try:
            conn = sqlite3.connect(os.path.join(DATABASE_DIR, 'master.db'))
            c = conn.cursor()
            c.execute("INSERT INTO votes (encrypted_vote, hmac, integrity_key) VALUES (?, ?, ?)",
                      (encrypted_vote, hmac_result, self.integrity_key.hex()))
            conn.commit()
            conn.close()
        except Exception as e:
            print("Erro ao armazenar o voto:", e)

    def retrieve_votes(self, password):
        """Recupera e decifra todos os votos da base de dados."""
        try:
            conn = sqlite3.connect(os.path.join(DATABASE_DIR, 'master.db'))
            c = conn.cursor()
            c.execute("SELECT encrypted_vote FROM votes")
            encrypted_votes = c.fetchall()
            conn.close()
            return [self.decrypt_vote(v[0], password) for v in encrypted_votes]
        except Exception as e:
            print("Erro ao recuperar os votos:", e)
            return []

def count_votes(current_user, Id_election):
    """Conta os votos válidos para cada partido e ordena por ordem de mais votos."""
    api = Database()
    result = api.get_votes(current_user, Id_election)
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
                key = bytes.fromhex(key_str)  # Converte a chave de integridade de hexadecimal para bytes
            except ValueError as e:
                print(f"Erro ao converter chave de integridade para bytes: {e}")
                continue  # Pula este registro de voto

            # Cria uma instancia temporaia do sistema de votacao com a chave correta
            temp_voting_system = VotingSystem()
            temp_voting_system.integrity_key = key

            # Verifica a integridade do voto
            if temp_voting_system.verify_hmac(partido, provided_hmac):
                if partido in vote_counts:
                    vote_counts[partido] += 1
                else:
                    vote_counts[partido] = 1

        # Ordena os partidos por numero de votos em ordem decrescente
        sorted_vote_counts = sorted(vote_counts.items(), key=lambda item: item[1], reverse=True)

        print("Contagem de votos por partido (ordenada):", sorted_vote_counts)
        return sorted_vote_counts

# Exemplo de uso
if __name__ == "__main__":
    iniciar_bd()
    voting_system = VotingSystem()
    admin_password = "admin_password"

    # Encrypt and store a vote
    vote = "option_1"
    voting_system.store_vote(vote, admin_password)

    # Retrieve and decrypt votes
    decrypted_votes = voting_system.retrieve_votes(admin_password)
    print("Decrypted votes:", decrypted_votes)

    # Generate and verify HMAC
    hmac_result = voting_system.generate_hmac(vote)
    print("Vote HMAC-SHA512:", hmac_result)
    is_valid = voting_system.verify_hmac(vote, hmac_result)
    print("HMAC verification:", "Valid" if is_valid else "Invalid")

    # Contagem de votos
    count_votes(4, 2)  # Assumindo current_user e 4 e Id_election e 2
