import hashlib
import hmac
import secrets
import os
import sys

sys.path.append('interface')
from VotingApp import start_app

current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)
from api.api_db import Database

class VotingSystem:
    def __init__(self):
        """Inicializa a classe gerando uma nova chave de integridade para a votação."""
        self.integrity_key = secrets.token_bytes(32)  # Gera uma chave segura de 256 bits

    def generate_hmac(self, vote):
        """Gera um HMAC-SHA512 para um voto usando a chave de integridade da votação atual."""
        vote_bytes = vote.encode('utf-8')
        return hmac.new(self.integrity_key, vote_bytes, hashlib.sha512).hexdigest()
    
    def verify_hmac(self, vote, provided_hmac):
        """Verifica o HMAC de um voto submetido comparando com um HMAC fornecido."""
        expected_hmac = self.generate_hmac(vote)
        return hmac.compare_digest(expected_hmac, provided_hmac)


def count_votes(current_user, Id_election):
    """Conta os votos válidos para cada partido e ordena por ordem de mais votos."""
    api = Database()
    result = api.get_votes(current_user, Id_election)
    if result.is_err():
        print("Erro ao obter votos:", result.message)
    else:
        votes = result.unwrap()
        
        # Dicionário para contar os votos por partido
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

            # Cria uma instância temporária do sistema de votação com a chave correta
            temp_voting_system = VotingSystem()
            temp_voting_system.integrity_key = key

            # Verifica a integridade do voto
            if temp_voting_system.verify_hmac(partido, provided_hmac):
                if partido in vote_counts:
                    vote_counts[partido] += 1
                else:
                    vote_counts[partido] = 1

        # Ordena os partidos por número de votos em ordem decrescente
        sorted_vote_counts = sorted(vote_counts.items(), key=lambda item: item[1], reverse=True)

        print("Contagem de votos por partido (ordenada):", sorted_vote_counts)
        return sorted_vote_counts




# Exemplo de uso
if __name__ == "__main__":
    voting_system = VotingSystem()
    votes = start_app()
    hmac_result = voting_system.generate_hmac(votes)
    
    is_valid = voting_system.verify_hmac(votes, hmac_result)

    api = Database()
    
    result = api.vote(current_user=4, Id_election=2, vote=votes, hmac=hmac_result, key=voting_system.integrity_key.hex())
    
    # Contagem de votos
    count_votes(2, 2)  # Assumindo current_user é 4 e Id_election é 2
