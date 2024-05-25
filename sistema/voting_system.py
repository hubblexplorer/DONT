import hashlib
import hmac
import secrets
import base64
import os
import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad



# Get the parent directory of the current script
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Add it to the system path if it's not already there
queue = []
if parent_dir not in sys.path:
    sys.path.append(parent_dir)
    if os.path.isdir(parent_dir):
        queue.append(parent_dir)

while queue:
    dir = queue.pop(0)
    for entry in os.scandir(dir):
        sys.path.append(entry.path)
        if entry.is_dir():
            queue.append(entry.path)

        
from interface.VotingApp import start_app
from api.api_db import Database
from shamir import Shamir
from resources.rsa_sign.keys_rsa import decrypt_message

class VotingSystem:
    def __init__(self, db: Database):
        """Inicia a classe que gera uma nova chave de integridade para a votação."""
        
        self.integrity_key = secrets.token_bytes(16)  # Gera uma chave segura de 256 bits
        print("CHAVE GERADA ALEATORIAMENTE: ",self.integrity_key)
        self.db = db

    def derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Deriva uma chave AES de 128 bits a partir da senha fornecida usando PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,  # 128 bits
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt_vote(self, vote: str) -> str:
        salt = secrets.token_bytes(16)
        key = self.derive_key(self.integrity_key, salt)
        iv = secrets.token_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        vote_bytes = vote.encode('utf-8')
        padded_vote_bytes = pad(vote_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded_vote_bytes)

        encrypted_data = base64.b64encode(iv + salt + ciphertext).decode('utf-8')
        return encrypted_data


    def decrypt_vote(self, encrypted_vote: str, key: bytes) -> str:
        stored_data = base64.b64decode(encrypted_vote)
        iv = stored_data[:16]
        salt = stored_data[16:32]
        ciphertext = stored_data[32:]

        derived_key = self.derive_key(key, salt)

        decipher = AES.new(derived_key, AES.MODE_CBC, iv)
        decrypted_padded = decipher.decrypt(ciphertext)
        try:
            decrypted = unpad(decrypted_padded, AES.block_size)
        except ValueError:
            print("Incorrect decryption")
            raise
        return decrypted.decode('utf-8')
        

    # Função para gerar HMAC
    def generate_hmac(self, vote: str, algorithm=hashlib.sha512,key:bytes = None):
        if key is None:
            key = self.integrity_key
        print("KEYYYYYYYY:",key)
        vote = vote.encode()
        return hmac.new(key, vote, algorithm).hexdigest()

    # Função para comparar HMACs de forma segura
    def verify_hmac(self, vote: str, key: bytes, hmac2:str):
        hmac1 = self.generate_hmac(vote,key=key)
        print("HMACCCCCC",hmac1)
        return hmac.compare_digest(hmac1, hmac2)
    
    def store_vote(self, current_user, election, vote, password):
        """Cifra e armazena um voto na base de dados."""
        encrypted_vote = self.encrypt_vote(vote)
        hmac_result = self.generate_hmac(vote)
        generated_key = self.encrypt_key(password)
        print("Chave: ",self.integrity_key)
        result =  self.db.vote(current_user,election,encrypted_vote,hmac_result,generated_key)
        if result.is_err():
            print("Erro ao armazenar o voto:", result.message)
        else:
            print("Voto armazenado com sucesso!")


    def retrieve_votes(self, current_user,id_election,password):
        """Recupera e decifra todos os votos da base de dados."""
        result = self.db.get_votes(current_user,id_election) 
        if result.is_err():
            print("Erro ao obter votos:", result.message)
        else:
            votes = []
            encrypted_votes = result.unwrap()
            for v in encrypted_votes:
                (vote,key) = self.decrypt_vote(v[0], password)
                result = self.verify_hmac(vote,v[1], key)
                print(vote)
                if not result:
                    print("Erro de verificação de hmac")
                else:                
                    votes.append(vote)
            return votes
        
    def encrypt_key(self, password: str) -> str:
        """Cifra a chave de integridade usando AES128-CBC com uma chave derivada da senha fornecida."""
        salt = secrets.token_bytes(16)
        key = self.derive_key(password.encode('utf-8'), salt)  # Convert password to bytes
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        vote_bytes = self.integrity_key  # Ensure this is in bytes
        padded_vote = vote_bytes + b"\0" * (16 - len(vote_bytes) % 16)
        ciphertext = encryptor.update(padded_vote) + encryptor.finalize()
        return urlsafe_b64encode(salt + iv + ciphertext).decode('utf-8')
        
    def decrypt_key(self, encrypted_key: str, password: str) -> bytes:
        # Ensure encrypted_key is a string for base64 decoding
        if isinstance(encrypted_key, bytes):
            encrypted_key = encrypted_key.decode('utf-8')

        # Add padding to base64 string if necessary
        missing_padding = len(encrypted_key) % 4
        if missing_padding:
            encrypted_key += '=' * (4 - missing_padding)

        # Decode the base64 string
        data = base64.urlsafe_b64decode(encrypted_key)

        # Extract salt, iv, and ciphertext
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]

        # Derive the key
        key = self.derive_key(password.encode('utf-8'), salt)

        # Set up the cipher to decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and remove padding
        padded_key = decryptor.update(ciphertext) + decryptor.finalize()
        return padded_key.rstrip(b"\0")

"""
if __name__ == "__main__":
# Chave secreta para integridade dos votos
    integrity_key = b'supersecretintegritykey'

    # Instancia o sistema de votação
    voting_system = VotingSystem(integrity_key)

    # Voto a ser registrado
    vote = 'Alice'

    # Gera o HMAC para o voto
    generated_hmac = voting_system.generate_hmac(vote)
    print(f'HMAC gerado para o voto "{vote}": {generated_hmac}')

    # Simula verificação do voto
    is_valid = voting_system.verify_hmac(vote, integrity_key, generated_hmac)
    print(f'O voto "{vote}" é válido? {is_valid}')

    # Teste com HMAC alterado (para simular um voto modificado ou inválido)
    altered_hmac = '0000000000000000000000000000000000000000000000000000000000000000'
    is_valid_altered = voting_system.verify_hmac(vote, integrity_key, altered_hmac)
    print(f'O voto "{vote}" com HMAC alterado é válido? {is_valid_altered}')
"""
"""
if __name__ == "__main__":
    voting_system = VotingSystem(b'secret_key')
    vote = "example_vote"
    generated_hmac = voting_system.generate_hmac(vote)
    print(f"Generated HMAC: {generated_hmac}")

    # Verificação
    message = vote.encode('utf-8')
    is_valid = voting_system.verify_hmac(message, generated_hmac, b'secret_key')
    print(f"Is the HMAC valid? {is_valid}")

"""