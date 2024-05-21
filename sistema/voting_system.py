import hashlib
import hmac
import secrets
import os
import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



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
        
from VotingApp import start_app
from api_db import Database
from shamir import Shamir
from keys_rsa import decrypt_message

class VotingSystem:
    def __init__(self, db: Database, password:bytes = None):
        """Inicia a classe que gera uma nova chave de integridade para a votação."""
        if  password == None:
            self.integrity_key = secrets.token_bytes(32)  # Gera uma chave segura de 256 bits
        else:
            self.integrity_key = password
 
        self.db = db

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

    def generate_hmac(self, vote, key=None):
        """Gera um HMAC-SHA512 para um voto usando a chave de integridade da votacao atual."""
        vote_bytes = vote.encode('utf-8')
        if  key is None:
            key = self.integrity_key
 
        return hmac.new(key, vote_bytes, hashlib.sha512).hexdigest()

    def verify_hmac(self, vote, provided_hmac, key = None):
        """Verifica o HMAC de um voto submetido comparando com um HMAC fornecido."""
        expected_hmac = self.generate_hmac(vote, key)
        return hmac.compare_digest(expected_hmac, provided_hmac)

    def store_vote(self, current_user, election, vote, password):
        """Cifra e armazena um voto na base de dados."""
        encrypted_vote = self.encrypt_vote(vote, password)
        hmac_result = self.generate_hmac(vote)
        
        result =  self.db.vote(current_user,election,encrypted_vote,hmac_result,password)
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
        

# Exemplo de uso
if __name__ == "__main__":
    db = Database()
    
    members = db.get_commission_members(1,1).unwrap()

    keys_parts = []
    print("Members:")

    for i,member in enumerate(members):
        key = member[2]
        file = open("keys/private_key_user"+str(i+2)+".pem", 'r')
        private_key = file.read()
        file.close()
        key, prime = decrypt_message(private_key,key).split('|DIV|')
        x, y = key.strip('(').strip(')').strip(' ').split(',')
        keys_parts.append((int(x),int(y)))
    
    

    shamir = Shamir(keys_parts,int(prime))
    vote = "option_1"

    secret: str = shamir.secret

    voting_system = VotingSystem(db, shamir.secret.encode())
    
    """
    # Encrypt and store a vote
    vote = "option_1"
    #voting_system.store_vote(3,1,vote, admin_password)

    # Retrieve and decrypt votes
    decrypted_votes = voting_system.retrieve_votes(2,1,admin_password)
    print("Decrypted votes: ", decrypted_votes)
    print("Number of votes: ", len(decrypted_votes))"""

    # Generate and verify HMAC
    encrypted_vot = voting_system.encrypt_vote(vote, shamir.secret)
   
    hmac_result = voting_system.generate_hmac(vote)
    print("Vote HMAC-SHA512:", hmac_result)

    decrypted_vote= voting_system.decrypt_vote(encrypted_vot, shamir.secret)

    
    print("Decrypted vote:", decrypted_vote)
   
    is_valid = voting_system.verify_hmac(vote, hmac_result, shamir.secret.encode())
    print("HMAC verification:", "Valid" if is_valid else "Invalid")

 
