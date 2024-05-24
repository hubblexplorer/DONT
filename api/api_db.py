#!/usr/bin/env python3

# Por causa de ficheiros em ficheiros diferentes, esta operação precisa ser feita
import secrets
import sys
import os


# Obter o ficheiro pai do script atual
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Adicione-o à variável de ambiente sys.path se não estiver lá já
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

from result import Result 
from datetime import timedelta
import datetime
import re
import sqlite3
import time
from shamir import Shamir

class Database:
	def __init__(self):
		self.conn = sqlite3.connect("resources/master.db")
		self.cursor = self.conn.cursor()

	# TODO: Change the login when signature verification is done
	def login(self, username: str, signcertificate: any) -> Result:
		"""
		Logs in a user based on the provided username and signature certificate.

		:param username: The username of the user attempting to log in.
		:param signcertificate: The signature certificate used for authentication.
		:return: Result object containing the following:
   			  	- Int: ID of the user if login is successful.
				- String: Role of the user if login is successful.
		"""
		self.cursor.execute("SELECT * FROM users WHERE username = ?", (username))
		raise NotImplementedError("Login needs signature implementation done")
	
	

	def clear_tables_except_admin(self) -> Result:
		"""
		Limpa todas as tabelas na banco de dados exceto o usuário com papel 'ADMIN'


		:return: Objeto Result indicando sucesso ou falha da operação.
		"""
		try:
			# Exclui todos os utilizador exceto o que tem papel 'ADMIN'.
			self.cursor.execute("DELETE FROM users WHERE role != 'ADMIN';")
			# Obtém as nomes de todas as tabelas na base de dados.
			self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
			tables = self.cursor.fetchall()

			# Percorre cada tabela e limpa-a se não for a 'users' tabela
			for table in tables:
				table_name = table[0]
				if table_name != 'Users':
					self.cursor.execute(f"DELETE FROM {table_name};")

			# Confirma a transação.
			self.conn.commit()
			return Result(value=True)
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro ocorreu ao limpar tabelas exceto utilizador")


	# Todas interações com a base de dados onde seja modificado os dados deve ser guardada
	def log(self, current_user: int, action: str, message: str) -> Result:
		"""
		Guarde uma ações feitas pelo utilizador

		:param current_user: O ID do utilizador atual.
		:param action: A ação realizada.
		:param message: Detalhes sobre a ação.
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		self.cursor.execute("INSERT INTO logs (timestamp, id_user, action, details) VALUES (?, ?, ?, ?)", (time.ctime(), str(current_user), action, message))
		self.conn.commit()
		return Result(value=True)
	
		
	def get_role(self, current_user:int ) -> Result:
		"""
   	 	Obtém o papel do utilizador

		:param current_user: O ID do utilizador atual.
		:return: Objeto de Result com o role se foi encontrado,
		ou uma mensagem de erro.
   	 	"""
		self.cursor.execute("SELECT role FROM users WHERE id = ?", (str(current_user)))
		aux = self.cursor.fetchone()
		if aux == None:
			return Result(error=True, message= "Utilizador não encontrado")
		return Result(value=aux[0])
	
	def get_id(self, table_name: str, column_username: str, value: str) -> Result:
		"""
		Obtém o id de uma tabela especifica baseada uma coluna especifica

		:param table_name: Nome da tabela
		:param column_username: Nome da coluna
		:param value: Valor a pesquisar
		:return: Objeto de Result com o id se foi encontrado,
		ou uma mensagem de erro.
		"""
		self.cursor.execute(f"SELECT id FROM {table_name} WHERE {column_username} = ?", (value,))
		aux = self.cursor.fetchone()
		if aux == None:
			return Result(error=True, message= "{Value} não encontrado em {table_name} ou coluna {column_username}")
		return Result(value=aux[0])
		
	
	def check_if_exists(self, table_name: str, column_name: str, value: str) -> bool:
		"""
		Verifica se um valor existe numa coluna de uma tabela específica

		:param table_name: Nome da tabela.
		:param column_username: Nome da coluna.
		:param value: Valor a pesquisar.
		:return: True se o valor existir, falso se não existir.
		"""

		self.cursor.execute(f"SELECT * FROM {table_name} WHERE {column_name} = ?", (value,))
		aux = self.cursor.fetchone()
		if aux == None:
			return False
		return True
	
	def create_user(self, current_user: int, new_username: str, new_pubkey: str, new_role: str) -> Result:
		"""
		Cria um novo utilizador na bd

		:param current_user: ID do utilizador atual, deve ser admin.
		:param new_username: Username do novo user.	
		:param new_pubkey: Chave publica do novo utilizador
		:param new_role: Papel do novo utilizador (ADMIN, USER, VOTER).
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "ADMIN": #Apenas admistradores podem criar users
			return Result(error=True, message="Apenas admistradores podem criar users")
		
		if new_role not in ["ADMIN", "USER", "VOTER"]: # Papeis possiveis
			return Result(error=True, message="Papel inválido")
		
		if self.check_if_exists("users", "pubkey", new_pubkey): # Verifica duplicado
			return Result(error=True, message="Chave pública já existe")
		
		try:
			self.conn.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO users (name, pubkey, role) VALUES (?, ?, ?)", (new_username, new_pubkey, new_role))
			return self.log(current_user, "CRIAR_USER", "User " + str(current_user) + " criou user " + new_username)
		
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro de SQL ocorreu a criar utilizador")


	def get_user_by_role(self, role: str) -> Result:
		"""
		Obtém os candidatos de uma certa eleições

		:return: Um objeto Result contém uma lista de nomes dos candidatos se encontrados, 
		ou uma mensagem de erro.
		"""
		try:
			self.cursor.execute("SELECT name FROM users WHERE role = ? ", (role,))
			aux = self.cursor.fetchall()
			if aux == None:
				return Result(error=True, message="Nenhum user foi encontrado")
			return Result(value=aux)
		except sqlite3.Error as e:
			print("Erro :", e)
			return Result(error=True, message="Erro de SQL a encontrar candidato")
		

	def get_candidates(self) -> Result:
		"""
		Obtém os candidatos de uma certa eleições

		:return: Um objeto Result contém uma lista de nomes dos candidatos se encontrados, 
		ou uma mensagem de erro.
		"""
		try:
			self.cursor.execute("SELECT name FROM candidates ")
			aux = self.cursor.fetchall()
			if aux == None:
				return Result(error=True, message="Sem candidatos encontrados")
			return Result(value=aux)
		except sqlite3.Error as e:
			print("Erro :", e)
			return Result(error=True, message="Erro de SQL a encontrar candidato")

	def add_candidate(self, current_user: int, candidate_name: str) -> Result:
		"""
		Adiciona um novo candidato

		:param current_user: ID do utilizador atual (admin ou user).
		:param candidate_name: Nome do candidato
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["ADMIN", "USER"]: 
			return Result(error=True, message="Apenas admins e users podem adicionar candidatos")
		
		if self.check_if_exists("candidates", "name", candidate_name):
			return Result(error=True, message="Candidato já exite")
		
		try:
			self.conn.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO candidates (name) VALUES (?)", (candidate_name,))
			return self.log(current_user, "ADICIONAR_CANDIDADO", "User " + str(current_user) + " adicionou " + candidate_name)
			 
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro :", e)
			self.conn.rollback()
			return Result(error=True, message="Erro de SQL a adicionar candidato")
		

	def get_candidates_by_election(self, election_id: int) -> Result:
		"""
		Obtém os candidatos de uma certa eleições

		:return: Um objeto Result contém uma lista de nomes dos candidatos se encontrados, 
		ou uma mensagem de erro.
		"""
		try:
			self.cursor.execute("SELECT id_candidate FROM elections_candidates where id_election = ?", (election_id,))
			aux = self.cursor.fetchall()
			self.cursor.execute("SELECT name FROM candidates WHERE id IN (?)", (aux,))
			aux = self.cursor.fetchall()
			if aux == None:
				return Result(error=True, message="No candidates ou um mensagem de erro indicando que nenhum candidato foi encontrado")
			return Result(value=aux)
		except sqlite3.Error as e:
			print("Erro :", e)
			return Result(error=True, message="Erro de SQL a encontrar candidato")

		

	def get_public_key(self, current_user: int) -> Result:
		"""
		Obtém a chave pública de um utilizador

		:param current_user: ID do utilizador que se quer a chave pública
		:return: Um objecto Result que contém a chave pública se encontrado,
			ou uma mensagem de erro.
		"""
		try:
			self.cursor.execute("SELECT pubkey FROM users WHERE id = ?", (current_user,))
			aux = self.cursor.fetchone()
			if aux == None:
				return Result(error=True, message="Chave pública não encontrada")
			return Result(value=aux[0])
		except sqlite3.Error as e:
			print("Erro :", e)
			return Result(error=True, message="Erro de SQL a encontrar chave pública")


	
	def create_election(self, current_user: int, list_user_Commission: list, list_candidates: list, name: str, start_date: str, end_date: str) -> Result:
		"""
		Creates a new election.

		:param current_user: ID do utilizador atual.
		:param list_user_Commission: Uma lista de Ids de utilizadores da comissão.
		:param list_candidates: Uma lista de nome dos candidatos da eleição.
		:param name: Nome da eleição.
		:param start_date: Início da eleição no formato DD-MM-YYYY.
		:param end_date: Fim da eleição no formato DD-MM-YYYY.
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux

		if aux.unwrap() not in ["ADMIN"]:
			return Result(error=True, message="Apenas admins podem criar eleições")
		
		# Verifica duplicados
		if self.check_if_exists("elections","name", name):
			return Result(error=True, message="Eleição " + name + " já existe")

		current_date = time.strftime("DD-MM-YYYY")

		# Verifica formatação da data 
		if not re.match(r'^\d{2}-\d{2}-\d{4}$', start_date):
			return Result(error=True, message="A data de início têm de estar no formato DD-MM-YYYY")

		if not re.match(r'^\d{2}-\d{2}-\d{4}$', end_date):
			return Result(error=True, message="A data de início têm de estar no formato DD-MM-YYYY")
		
		if current_date < start_date:
			return Result(error=True, message="A data de ínicio tem de ser depois da data atual")
		if current_date < end_date:
			return Result(error=True, message="A data de fim tem de ser depois da data atual")
		
		if len(list_candidates) < 2:
			return Result(error=True, message="A eleição deve ter pelo menos 2 candidatos")
		
		list_candidates_ids = []
		for candidate in list_candidates:

			if not self.check_if_exists("candidates", "name", candidate):
				return Result(error=True, message="Candidato " + candidate + " não exite")
			
			list_candidates_ids.append(self.get_id("candidates", "name", candidate).unwrap())

		for user in list_user_Commission:
			if not self.check_if_exists("users", "name", user):
				if self.get_role(user).unwrap() != "USER":
					return Result(error=True, message="User " + str(user) + " não é user")
		
		# Cria número para a nova comissão
		try:
			self.cursor.execute("SELECT COUNT(*) FROM Commissions")
			number_commission = self.cursor.fetchone()[0]

		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro SQL durante a criação de uma eleição")

		number_commission = int(number_commission) + 1

		secret_key = secrets.token_bytes(32)

		shamir_secrets = Shamir(len(list_user_Commission), secret_key)

		secret_sharing_scheme = shamir_secrets.secret_sharing_scheme

		

		encypted_keys = []
		for pos,key in enumerate(list_user_Commission):
			key = self.get_public_key(self.get_id("users", "name", key).unwrap()).unwrap()
			encypted_keys.append(encrypt_message(key, str(secret_sharing_scheme[pos])+"|DIV|" + str(shamir_secrets.prime)))
					
		try:
			self.cursor.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO elections (Name, Is_Active, start_date, end_date, Id_commission) VALUES (?, ?, ?, ?, ?)", (name, False, start_date, end_date, number_commission))
			id_election = self.cursor.lastrowid
			self.cursor.execute("INSERT INTO Commissions (ID, Id_election, num_members) VALUES (?, ?,?)", (number_commission, id_election, len(list_user_Commission)))
			for pos,user in enumerate(list_user_Commission):
				self.cursor.execute("INSERT INTO Commission_members (Id_commission, Id_user, SHAMIR_SECRET_ENCRYPTED) VALUES (?, ?, ?)", (number_commission, user, encypted_keys[pos]))
			for candidate in list_candidates_ids:
				self.cursor.execute("INSERT INTO election_candidates (Id_election, Id_candidates) VALUES (?, ?)", (id_election, candidate))
			return self.log(current_user, "CRIAR_ELEIÇÃO", "User " + str(current_user) + " criou a eleição " + name)
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro SQL durante a criação de uma eleição")
		
	def get_elections_by_user(self, current_user: int) -> Result:
		"""
		Obtém as eleições que o utilizador está associado

		:param current_user: ID do utilizador atual
		:return: Um objecto Result que contém as eleições se encontrado,
			ou uma mensagem de erro.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["USER"]:
			return Result(error=True, message="Apenas user podem estar associados a eleições")
		try:
			self.cursor.execute("""
				SELECT e.*
				FROM elections e
				JOIN commission_members cm ON e.id_commission = cm.id_commission
				WHERE cm.id_user = ?
			""", (current_user,))
			elections = self.cursor.fetchall()
			if not elections:
				return Result(error=True, message="Nenhuma eleição encontrada para o utilizador")
			return Result(value=elections)
		except sqlite3.Error as e:
			print("Erro: ", e)
			return Result(error=True, message="Erro SQL ocurreu a obter eleições")
	
	def get_elections_global(self) -> Result:
		try:
			self.cursor.execute("SELECT id, Name FROM elections WHERE Is_Active = 1")
			elections = self.cursor.fetchall()
			if not elections:
				return Result(error=True, message="Sem eleições criadas")
			return Result(value=elections)
		except sqlite3.Error as e:
			print("Erro: ", e)
			return Result(error=True, message="Erro SQL ocurreu a obter eleições")


	def change_election_active_status(self, current_user: int, Id_election: int, status: bool) -> Result:
		"""
		Altera o estado da elieção para ativo

		:param current_user: ID do utilizador atual.
		:param Id_election: ID da eleição a alterar.
		:param status: Novo estado da eleição. (False -> Fechado | True -> Aberto)
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["USER"]:
			self.log(current_user, "ERRO: PERMISSÃO_NEGADA", "User " + str(current_user) + " tentou alterar estado da eleição " + str(Id_election) + " mas este não é um user")
			return Result(error=True, message="Apenas users podem mudar o estado a eleição, isto irá ser reportado")
		
		# Verificar se a data está nos limites.
		#current_date = time.strftime("DD-MM-YYYY")

		#try:
		#	aux = self.cursor.execute("SELECT start_date, end_date FROM elections WHERE Id = ?", (Id_election,))
		#except sqlite3.Error as e:
		#	print("Erro:", e)
		#	return Result(error=True, message="Erro SQL a obter as datas da eleição")
		
		#start_date, end_date = aux.fetchone()
		#if status:
		#	if current_date < start_date or current_date > end_date:
		#		self.log(current_user,"ERROR: PERMISSÃO_NEGADA", "User " + str(current_user) + "  tentou alterar estado da eleição " + str(Id_election) + " que não pode ser alterada nesta data")
		#			return Result(error=True, message="Eleição " + str(Id_election) + " não pode ser alterada pois não a data atual não é a correta, isto irá ser reportado.")

		# Verificações concluidas
  
		try: 
			self.cursor.execute("BEGIN TRANSACTION")
			self.cursor.execute("UPDATE elections SET Is_Active = ? WHERE Id = ?", (status, Id_election,))
			return self.log(current_user, "CHANGE_ELECTION_STATUS", "User " + str(current_user) + " changed election status of election " + str(Id_election))
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro SQL a alterar estado da eleição")
			
	def vote(self, current_user: int, Id_election: int, vote: str, hmac: str, key: str) -> Result:
		"""
		Regista um voto para uma eleição

		:param current_user: ID do utilizador atual.
		:param Id_election: ID da eleição.
		:param vote: O voto encriptado do utilizador.
		:param hmac: HMAC do voto.
		:return: Objeto de Result indicando sucesso ou falha.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "VOTER":
			self.log(current_user, "ERRO: PERMISSÃO_NEGADA", "User " + str(current_user) + " tentou votar na eleição " + str(Id_election) + " mas este não é um voter")
			return Result(error=True, message="Apenas Voter podem votar, isto irá ser reportado")
		
		if not self.check_if_exists("elections", "Id", Id_election):
			return Result(error=True, message="Eleição " + str(Id_election) + " não exite")
		
		# Verifica se utilizador votou
		try :
			aux = self.cursor.execute("SELECT Count(*) FROM Election_voters WHERE Id_voter = ? AND Id_election = ?", (current_user, Id_election))
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			return Result(error=True, message="ERRO SQL a verifcar se voto já existe")
		
		if aux.fetchone()[0] > 0:
			self.log(current_user, "ERRO: VOTO_DUPLICADO", "UTILIZADOR " + str(current_user) + " tentou votar novamente na eleição " + str(Id_election) + " que já votou antes")
			return Result(error=True, message="Voter " + str(current_user) + " já votou, isto irá ser reportado")
		
		# Verifca se a eleição está ativa
		try :
			aux = self.cursor.execute("SELECT Is_Active FROM elections WHERE Id = ?", (Id_election,))
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro SQL a verificar se a eleição está ativa")


		if not aux.fetchone()[0]:
			self.log(current_user,"ERRO: PERMISSÃO_NEGADA", "USER "+ str(current_user) + " tentou votar na eleição " + str(Id_election) + " que não está ativa")
			return Result(error=True, message="ELEIÇÃO " + str(Id_election) + " não está ativa, isto irá ser reportado")

		try: 
			self.cursor.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO Votes (Vote,Hmac,ID_election,Key) VALUES (?, ?, ?,?)", (vote, hmac, Id_election, key))
			self.cursor.execute("INSERT INTO Votes (Vote,Hmac,ID_election,Key) VALUES (?, ?, ?,?)", (vote, hmac, Id_election, key))
			self.cursor.execute("INSERT INTO Election_voters (Id_voter, Id_election) VALUES (?, ?)", (current_user, Id_election))
			return self.log(current_user, "VOTE", "User " + str(current_user) + " votou na eleição " + str(Id_election))
		except sqlite3.Error as e:
			# Rollback a transação se ocorrer um erro.
			print("Erro:", e)
			self.conn.rollback()
			return Result(error=True, message="Erro SQL quando user " + str(current_user) + " votava, voto não contado")

	def get_votes(self, current_user: int, Id_election: int) -> Result:
		"""
		Obtém os votos de uma determinada eleição

		:param current_user: ID do utilizador atual.
		:param Id_election: ID da eleição.
		:return: Um objecto Result que contém todos os votos de uma eleição,
			ou uma mensagem de erro.
		"""

		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "USER":
			self.log(current_user, "ERRO: PERMISSÃO_NEGADA", "User " + str(current_user) + " tentou obter os votos da eleição " + str(Id_election) + " mas não está autorizado")
			return Result(error=True, message="Apenas utilizadores pode aceder a votos, isto irá ser reportado")

		#Check if user is in the Commission
		if not self.check_if_exists("Commission_members", "Id_user", current_user):
			self.log(current_user, "ERRO: PERMISSÃO_NEGADA", "User " + str(current_user) + " tentou obter os votos da eleição " + str(Id_election) + " mas não está autorizado")
			return Result(error=True, message="User " + str(current_user) + " não pertence a comissão desta eleição, isto irá ser reportado")

		try:
			self.cursor.execute("SELECT Vote, Hmac, key FROM Votes WHERE ID_election = ?", (Id_election,))
			votes = self.cursor.fetchall()
			return Result(error=False, value=votes)
		except sqlite3.Error as e:
			print("Erro:", e)
			return Result(error=True, message="Erro SQL a obter votos")

	def get_logs(self, current_user: int) -> Result: 
		"""
		Obtém os logs do sistema.

		:param current_user: ID do utilizador atual.
		:return: Um objecto Result que contém todos os logs do sistema
			ou uma mensagem de erro.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "ADMIN":
			self.log(current_user, "ERRO: PERMISSÃO_NEGADA", "User "+ str(current_user) + " tentou aceder aos logs")
			return Result(error=True, message="Apenas admins podem aceder aos votos, isto irá ser reportado")
		
		try:
			self.cursor.execute("SELECT * FROM Logs")
			logs = self.cursor.fetchall()
			return Result(error=False, value=logs)
		except sqlite3.Error as e:
			print("Erro:", e)
			return Result(error=True, message="Erro SQL a obter os votos")
		
	def get_commission_members(self, current_user: int, Commission_id: int) -> Result:
		"""
		Obtém os membros de uma comissão

		:param Commission_id: ID da comissão
		:return: Um objecto Result que contém os ids de 
			ou uma mensagem de erro.
		"""
		if not self.check_if_exists("Commission_members", "Id_commission", Commission_id):
			return Result(error=True, message="Commission " + str(Commission_id) + " does not exist")
		
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["ADMIN", "USER"]:
			return Result(error=True, message="Apenas admins e users podem aceder a membros da comissão")
		
		try:
			self.cursor.execute("SELECT * FROM Commission_members WHERE Id_commission = ?", (Commission_id,))
			members = self.cursor.fetchall()
			return Result(error=False, value=members)
		except sqlite3.Error as e:
			print("Erro:", e)
			return Result(error=True, message="Erro SQL a obter membros de uma comissão")
		
		




#############
### TESTS ###
#############


import unittest
from resources.rsa_sign.keys_rsa import encrypt_message, generate_rsa_keypair
class DatabaseTest(unittest.TestCase):

	def setUp(self):
		self.db = Database()
		self.db.clear_tables_except_admin()



	def test_get_role(self):
		aux = self.db.get_role(1)
		self.assertEqual(aux.is_ok(), True)
		self.assertEqual(aux.unwrap(), "ADMIN")


	def test_create_user(self):
		private_key, public_key = generate_rsa_keypair()
		# Guarda a chaves privadas dos utilizadores

		new_file = open("keys/private_key_user2.pem", "w")
		new_file.write(private_key)
		new_file.close()

		self.assertTrue(self.db.create_user(1, "user2", public_key, "USER").unwrap())


		private_key, public_key = generate_rsa_keypair()
		# Guarda a chaves privadas dos utilizadores
		new_file = open("keys/private_key_user5.pem", "w")
		new_file.write(private_key)
		new_file.close()

		self.assertTrue(self.db.create_user(1, "user5", public_key, "VOTER").unwrap())

	def test_add_candidate(self):
		self.assertTrue(self.db.add_candidate(1, "candidate1").unwrap())
		self.assertTrue(self.db.add_candidate(1, "candidate2").unwrap())


	
	def test_error_create_user(self):
		try: 
			aux = self.db.create_user(2, "user1", "pubkey1", "USER").unwrap()
			print(aux)
			self.assertFalse(aux)

		except:
			print("Erro esperado")
			self.assertTrue(True)



	def test_create_election(self):
		for i in range(1, 3):
			private_key, public_key = generate_rsa_keypair()
			file_name = "keys/private_key_user" + str(i+2) + ".pem"
			new_file = open(file_name, "w")
			new_file.write(private_key)
			new_file.close()
			self.assertTrue(self.db.create_user(1, "user" + str(i+2), public_key, "USER").unwrap())
		
		list_of_users = [2, 3, 4]

		self.assertTrue(self.db.create_election(1, list_of_users, ["candidate1", "candidate2"], "election1", "01-01-2025", "02-01-2025").unwrap())

	def test_vote(self):

		#Criar uma eleição falsa para testar
		current_time = datetime.datetime.now()
		start_date =  current_time - timedelta(days=1)
		end_date = current_time + timedelta(days=1)

		start_date = start_date.strftime("%d-%m-%Y")
		end_date = end_date.strftime("%d-%m-%Y")

		self.db.cursor.execute("INSERT INTO Elections (Name, Is_Active, Start_Date, End_date, Id_Commission) VALUES (?, ?, ?, ?, ?)", ("election1", True, start_date, end_date, 1))
		self.db.cursor.execute("INSERT INTO Election_Candidates (Id_Election, Id_Candidates) VALUES (?, ?)", (2, 1))
		self.db.conn.commit()

		for i in range(1, 7):
			private_key, public_key = generate_rsa_keypair()
			file_name = "keys/private_key_user" + str(i+4) + ".pem"
			new_file = open(file_name, "w")
			new_file.write(private_key)
			new_file.close()
			self.assertTrue(self.db.create_user(1, "user" + str(i+4), public_key, "VOTER").unwrap())


		self.assertTrue(self.db.vote(5, 2, "candidate1", "hmac1",'8248278').unwrap())
		self.assertTrue(self.db.vote(6, 2, "candidate1", "hmac1",'8248278').unwrap())


	
	def test_vote_again(self):
		try: 
			self.db.vote(5, 2, "candidate1", "hmac1", '8248278').unwrap()
			self.db.vote(6, 2, "candidate1", "hmac1", '8248278').unwrap()
		except:
			print("Erro esperado")
			self.assertTrue(True)

	def test_get_votes(self):

		
		aux = self.db.get_votes(2, 2)
		if aux.is_err():
			print(aux.error)
			self.assertTrue(False)
		
		for vote in aux.unwrap():
			print(vote)
		self.assertTrue(True)
			
	

	def test_get_logs(self):
		try:
			aux = self.db.get_logs(1).unwrap()
			for line in aux:
				print(line)
		except:
			self.assertTrue(False)


	def test_get_elections(self):
		
		result = self.db.get_elections_global(3)
		if result.is_err():
			print(result.message)
			self.assertTrue(False)
		elections = result.unwrap()
		for election in elections:
			print(election)
		self.assertTrue(True)

	

	def tearDown(self):
		self.db.conn.close()

def test_db():
	print(r'AVISO: ISTO IRÁ DESTRUI TODOS OS DADOS DA BASE DE DADOS\n')
	I = input('Tem a certeza: (S/n) ')
	if I != 'S':
		print('Abortado')
		return
	
	print("A correr testes")
	
	dbtest = DatabaseTest()
	dbtest.setUp()	
	dbtest.test_get_role()
	dbtest.test_create_user()
	dbtest.test_add_candidate()
	dbtest.test_error_create_user()
	dbtest.test_create_election()
	#dbtest.test_vote()
	#dbtest.test_vote_again()
	#dbtest.test_get_votes()
	dbtest.test_get_logs()
	#dbtest.test_get_elections()
	dbtest.tearDown()
	print("Todos os testes efectuados com sucesso")
	

#test_db()
