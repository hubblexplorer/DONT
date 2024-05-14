import hashlib
import hmac
import secrets

import sys
sys.path.append('../interface')
from VotingApp import start_app

class VotingSystem:
    def __init__(self):
        """Inicializa a classe gerando uma nova chave de integridade para a votação."""
        self.integrity_key = secrets.token_bytes(32)  # Gera uma chave segura de 256 bits

    def generate_hmac(self, vote):
        """Gera um HMAC-SHA512 para um voto usando a chave de integridade da votação atual."""
        # Converte o voto em bytes, assumindo que o voto é uma string
        vote_bytes = vote.encode('utf-8')
        # Cria um novo HMAC usando a chave de integridade e SHA512
        return hmac.new(self.integrity_key, vote_bytes, hashlib.sha512).hexdigest()
    
    def verify_hmac(self, vote, provided_hmac):
        """Verifica o HMAC de um voto submetido comparando com um HMAC fornecido."""
        # Gera um novo HMAC com base no voto para comparação
        expected_hmac = self.generate_hmac(vote)
        # Compara o HMAC fornecido com o esperado
        return hmac.compare_digest(expected_hmac, provided_hmac)

# Exemplo de uso
if __name__ == "__main__":
    start_app()
    voting_system = VotingSystem()
    vote = "opcao_de_voto_1"
    hmac_result = voting_system.generate_hmac(vote)
    print("HMAC-SHA512 do voto:", hmac_result)
    
    # Verificar o HMAC
    is_valid = voting_system.verify_hmac(vote, hmac_result)
    print("Verificação do HMAC:", "Válido" if is_valid else "Inválido")