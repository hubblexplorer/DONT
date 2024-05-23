#!/usr/bin/env python3

#Because of files in different directories this mess has to be done
import secrets
import sys
import os


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
		Clears all tables in the database except the admin user

		:return: Result object indicating success or failure of the operation.
		"""
		try:
			# Delete all users except the one with role 'ADMIN'
			self.cursor.execute("DELETE FROM users WHERE role != 'ADMIN';")
			# Get the names of all tables in the database
			self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
			tables = self.cursor.fetchall()

			# Loop through each table and clear it if it's not the 'users' table
			for table in tables:
				table_name = table[0]
				if table_name != 'Users':
					self.cursor.execute(f"DELETE FROM {table_name};")

			# Commit the transaction
			self.conn.commit()
			return Result(value=True)
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="Error occurred while clearing tables except users")


	# Every interaction with database where data is modify should be log
	def log(self, current_user: int, action: str, message: str) -> Result:
		"""
		Logs an action performed by a user.

		:param current_user: The ID of the current user.
		:param action: The action performed.
		:param message: Details about the action.
		:return: Result object indicating success or failure.
		"""
		self.cursor.execute("INSERT INTO logs (timestamp, id_user, action, details) VALUES (?, ?, ?, ?)", (time.ctime(), str(current_user), action, message))
		self.conn.commit()
		return Result(value=True)
	
		
	def get_role(self, current_user:int ) -> Result:
		"""
   	 	Retrieves the role of a user.

		:param current_user: The ID of the current user.
		:return: Result object containing the user's role if found,
			 otherwise an error message indicating the user was not found.
   	 	"""
		self.cursor.execute("SELECT role FROM users WHERE id = ?", (str(current_user)))
		aux = self.cursor.fetchone()
		if aux == None:
			return Result(error=True, message= "User not found")
		return Result(value=aux[0])
	
	def get_id(self, table_name: str, column_username: str, value: str) -> Result:
		"""
		Retrieves the ID from a specified table based on the username column.

		:param table_name: The name of the table to query.
		:param column_username: The name of the column containing usernames.
		:param value: The value to search for in the username column.
		:return: Result object containing the ID if found,
			 otherwise an error message indicating the ID was not found.
		"""
		self.cursor.execute(f"SELECT id FROM {table_name} WHERE {column_username} = ?", (value,))
		aux = self.cursor.fetchone()
		if aux == None:
			return Result(error=True, message= "Id not found")
		return Result(value=aux[0])
		
	
	def check_if_exists(self, table_name: str, column_name: str, value: str) -> bool:
		"""
		Checks if a value exists in a specific column of a table.

		:param table_name: The name of the table to search.
		:param column_name: The name of the column to search.
		:param value: The value to search for in the column.
		:return: True if the value exists in the column, False otherwise.
		"""

		self.cursor.execute(f"SELECT * FROM {table_name} WHERE {column_name} = ?", (value,))
		aux = self.cursor.fetchone()
		if aux == None:
			return False
		return True
	


	# TODO: Change the new_pubkey type
	def create_user(self, current_user: int, new_username: str, new_pubkey: any, new_role: str) -> Result:
		"""
		Creates a new user in the system.

		:param current_user: The ID of the current user (admin).
		:param new_username: The username of the new user.
		:param new_pubkey: The public key associated with the new user.
		:param new_role: The role of the new user (ADMIN, USER, VOTER).
		:return: Result object indicating success or failure of the operation.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "ADMIN": #Only admins should create users
			return Result(error=True, message="Only admins can create users")
		
		if new_role not in ["ADMIN", "USER", "VOTER"]: # Available roles
			return Result(error=True, message="Invalid role")
		
		if self.check_if_exists("users", "pubkey", new_pubkey): # Check for duplicates
			return Result(error=True, message="Public key already exists")
		
		if self.check_if_exists("users", "name", new_username): # Check for duplicates
			return Result(error=True, message="Username already exists")
		
		try:
			self.conn.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO users (name, pubkey, role) VALUES (?, ?, ?)", (new_username, new_pubkey, new_role))
			return self.log(current_user, "CREATE_USER", "User " + str(current_user) + " created user " + new_username)
		
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while creating user")
	

	def add_candidate(self, current_user: int, candidate_name: str) -> Result:
		"""
		Adds a new candidate to the system.

		:param current_user: The ID of the current user (admin or regular user).
		:param candidate_name: The name of the candidate to be added.
		:return: Result object indicating success or failure of the operation.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["ADMIN", "USER"]: 
			return Result(error=True, message="Only admins and users can add candidates")
		
		if self.check_if_exists("candidates", "name", candidate_name):
			return Result(error=True, message="Candidate already exists")
		
		try:
			self.conn.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO candidates (name) VALUES (?)", (candidate_name,))
			return self.log(current_user, "ADD_CANDIDATE", "User " + str(current_user) + " added candidate " + candidate_name)
			 
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while adding candidate")
		

	def get_candidates_by_election(self, election_id: int) -> Result:
		"""
		Retrieves a list of all candidates in the system.

		:return: Result object containing a list of candidate names if found,
			 otherwise an error message indicating no candidates were found.
		"""
		try:
			self.cursor.execute("SELECT id_candidate FROM elections_candidates where id_election = ?", (election_id,))
			aux = self.cursor.fetchall()
			self.cursor.execute("SELECT name FROM candidates WHERE id IN (?)", (aux,))
			aux = self.cursor.fetchall()
			if aux == None:
				return Result(error=True, message="No candidates found")
			return Result(value=aux)
		except sqlite3.Error as e:
			print("Error occurred:", e)


		

	def get_public_key(self, current_user: int) -> Result:
		"""
		Retrieves the public key of a user.

		:param current_user: The ID of the user whose public key is to be retrieved.
		:return: Result object containing the public key if found,
			 otherwise an error message indicating the public key was not found.
		"""
		try:
			self.cursor.execute("SELECT pubkey FROM users WHERE id = ?", (current_user,))
			aux = self.cursor.fetchone()
			if aux == None:
				return Result(error=True, message="Public key not found")
			return Result(value=aux[0])
		except sqlite3.Error as e:
			print("Error occurred:", e)


	
	def create_election(self, current_user: int, list_user_Commission: list, list_candidates: list, name: str, start_date: str, end_date: str) -> Result:
		"""
		Creates a new election.

		:param current_user: The ID of the current user creating the election.
		:param list_user_Commission: A list of user IDs participating in the election.
		:param list_candidates: A list of candidate names participating in the election.
		:param name: The name of the election.
		:param start_date: The start date of the election in DD-MM-YYYY format.
		:param end_date: The end date of the election in DD-MM-YYYY format.
		:return: Result object indicating success or failure of the operation.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux

		if aux.unwrap() not in ["ADMIN"]:
			return Result(error=True, message="Only ADMIN should create elections")
		
		#Check for duplicates 
		if self.check_if_exists("elections","name", name):
			return Result(error=True, message="Election " + name + " already exists")
		if start_date > end_date:
			return Result(error=True, message="Start date must be before end date")
		current_date = time.strftime("DD-MM-YYYY")

		#check date formating 
		if not re.match(r'^\d{2}-\d{2}-\d{4}$', start_date):
			return Result(error=True, message="Start date must be in DD-MM-YYYY format")

		if not re.match(r'^\d{2}-\d{2}-\d{4}$', end_date):
			return Result(error=True, message="End date must be in DD-MM-YYYY format")
		
		if current_date < start_date:
			return Result(error=True, message="Election must start after current date")
		if current_date < end_date:
			return Result(error=True, message="Election must end after current date")
		
		if end_date < start_date:
			return Result(error=True, message="End date must be after start date")
		
		if len(list_candidates) < 2:
			return Result(error=True, message="Election must have at least 2 candidates")
		
		list_candidates_ids = []
		for candidate in list_candidates:

			if not self.check_if_exists("candidates", "name", candidate):
				return Result(error=True, message="Candidate " + candidate + " does not exist")
			
			list_candidates_ids.append(self.get_id("candidates", "name", candidate).unwrap())

		for user in list_user_Commission:
			if not self.check_if_exists("users", "id", user):
				if self.get_role(user).unwrap() != "USER":
					return Result(error=True, message="User " + str(user) + " is not an admin")
		
		#Get number of commission
		try:
			self.cursor.execute("SELECT COUNT(*) FROM Commissions")
			number_commission = self.cursor.fetchone()[0]

		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while creating election")

		number_commission = int(number_commission) + 1

		secret_key = secrets.token_bytes(32)

		shamir_secrets = Shamir(len(list_user_Commission), secret_key)

		secret_sharing_scheme = shamir_secrets.secret_sharing_scheme

		

		encypted_keys = []
		for pos,key in enumerate(list_user_Commission):
			key = self.get_public_key(key).unwrap()
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
			return self.log(current_user, "CREATE_ELECTION", "User " + str(current_user) + " created election " + name)
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while creating election")
		
	def get_elections_by_user(self, current_user: int) -> Result:
		"""
		Gets elections with commission information

		:param current_user: The ID of the current user.
		:return: Result object containing the election information.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["USER", "ADMIN"]:
			return Result(error=True, message="Only USER and ADMIN should get elections")
		try:
			self.cursor.execute("""
				SELECT e.*
				FROM elections e
				JOIN commission_members cm ON e.id_commission = cm.id_commission
				WHERE cm.id_user = ?
			""", (current_user,))
			elections = self.cursor.fetchall()
			if not elections:
				return Result(error=True, message="No elections found for the user")
			return Result(value=elections)
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while retrieving elections")
	
	def get_elections_global(self) -> Result:
		try:
			self.cursor.execute("SELECT id FROM elections")
			elections = self.cursor.fetchall()
			if not elections:
				return Result(error=True, message="No elections found for the user")
			return Result(value=elections)
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while retrieving elections")


	def change_election_active_status(self, current_user: int, Id_election: int, status: bool) -> Result:
		"""
		Changes the active status of an election.

		:param current_user: The ID of the current user attempting to change the status.
		:param Id_election: The ID of the election to change the status of.
		:param status: The new active status to set for the election.
		:return: Result object indicating success or failure of the operation.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["USER"]:
			self.log(current_user, "ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to change election status of election " + str(Id_election) + " which is not a user")
			return Result(error=True, message="Only USER should change election status, this will be reported")
		
		#Check if the time is right
		current_date = time.strftime("DD-MM-YYYY")

		try:
			aux = self.cursor.execute("SELECT start_date, end_date FROM elections WHERE Id = ?", (Id_election,))
		except sqlite3.Error as e:
			print("Error occurred:", e)
			return Result(error=True, message="SQL Error occurred while getting election start and end date")
		
		start_date, end_date = aux.fetchone()
		if status:
			if current_date < start_date or current_date > end_date:
				self.log(current_user,"ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to change election status of election " + str(Id_election) + " while can't be changed due to time")
				return Result(error=True, message="Election " + str(Id_election) + " cannot be changed due to time, this will be reported")
		else: 
			if current_date > start_date and current_date < end_date:
				self.log(current_user,"ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to change election status of election " + str(Id_election) + " while can't be changed due to time")
				return Result(error=True, message="Election " + str(Id_election) + " cannot be be closed due to time, this will be reported")
		#Checks done
  
		try: 
			self.cursor.execute("BEGIN TRANSACTION")
			self.cursor.execute("UPDATE elections SET Is_Active = ? WHERE Id = ?", (status, Id_election,))
			return self.log(current_user, "CHANGE_ELECTION_STATUS", "User " + str(current_user) + " changed election status of election " + str(Id_election))
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while creating election")
			
	def vote(self, current_user: int, Id_election: int, vote: any, hmac: str, key: str) -> Result:
		"""
		Registers a vote in the specified election.

		:param current_user: The ID of the user attempting to vote.
		:param Id_election: The ID of the election in which the user is voting.
		:param vote: The vote cast by the user.
		:param hmac: HMAC of the vote for security verification.
		:return: Result object indicating success or failure of the operation.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "VOTER":
			self.log(current_user, "ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to vote on election " + str(Id_election) + " which is not a voter")
			return Result(error=True, message="Only VOTER should vote, this will be reported")
		
		if not self.check_if_exists("elections", "Id", Id_election):
			return Result(error=True, message="Election " + str(Id_election) + " does not exist")
		
		#Check if voter as already voted
		try :
			aux = self.cursor.execute("SELECT Count(*) FROM Election_voters WHERE Id_voter = ? AND Id_election = ?", (current_user, Id_election))
		except sqlite3.Error as e:
			# Rollback the transaction if an error occurs
			print("Error occurred:", e)
			return Result(error=True, message="SQL Error occurred while checking if voter has already voted")
		
		if aux.fetchone()[0] > 0:
			self.log(current_user, "ERROR: DUPLICATE_VOTE", "User " + str(current_user) + " tried to vote in election " + str(Id_election) + " which has already been voted")
			return Result(error=True, message="Voter " + str(current_user) + " has already voted, this will be reported")
		
		#Check if its active
		try :
			aux = self.cursor.execute("SELECT Is_Active FROM elections WHERE Id = ?", (Id_election,))
		except sqlite3.Error as e:
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while checking if election is active")


		if not aux.fetchone()[0]:
			self.log(current_user,"ERROR: PERMISSION_DENIED", "USER "+ str(current_user) + " tried to vote in election " + str(Id_election) + " which is not active")
			return Result(error=True, message="Election " + str(Id_election) + " is not active, this will be reported")
		
		#checks are done
		try: 
			self.cursor.execute("BEGIN TRANSACTION")
			self.cursor.execute("INSERT INTO Votes (Vote,Hmac,ID_election,Key) VALUES (?, ?, ?,?)", (vote, hmac, Id_election, key))
			self.cursor.execute("INSERT INTO Votes (Vote,Hmac,ID_election,Key) VALUES (?, ?, ?,?)", (vote, hmac, Id_election, key))
			self.cursor.execute("INSERT INTO Election_voters (Id_voter, Id_election) VALUES (?, ?)", (current_user, Id_election))
			return self.log(current_user, "VOTE", "User " + str(current_user) + " voted in election " + str(Id_election))
		except sqlite3.Error as e:
			print("Error occurred:", e)
			self.conn.rollback()
			return Result(error=True, message="SQL Error occurred while voting")

	def get_votes(self, current_user: int, Id_election: int) -> Result:
		"""
		Retrieves the votes cast in the specified election.

		:param current_user: The ID of the user requesting the votes.
		:param Id_election: The ID of the election for which votes are being requested.
		:return: Result object containing the votes if successful, otherwise an error message.
		"""

		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "USER":
			self.log(current_user, "ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to get votes for election " + str(Id_election))
			return Result(error=True, message="Only USER should get votes, this will be reported")

		#Check if user is in the Commission
		if not self.check_if_exists("Commission_members", "Id_user", current_user):
			self.log(current_user, "ERROR: PERMISSION_DENIED", "User " + str(current_user) + " tried to get votes for election " + str(Id_election))
			return Result(error=True, message="User " + str(current_user) + " is not in the Commission, this will be reported")

		try:
			self.cursor.execute("SELECT Vote, Hmac, key FROM Votes WHERE ID_election = ?", (Id_election,))
			self.cursor.execute("SELECT Vote, Hmac, key FROM Votes WHERE ID_election = ?", (Id_election,))
			votes = self.cursor.fetchall()
			return Result(error=False, value=votes)
		except sqlite3.Error as e:
			print("Error occurred:", e)
			return Result(error=True, message="SQL Error occurred while voting")

	def get_logs(self, current_user: int) -> Result: 
		"""
		Retrieves the logs of the system.

		:param current_user: The ID of the user requesting the logs.
		:return: Result object containing the logs if successful, otherwise an error message.
		"""
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() != "ADMIN":
			self.log(current_user, "ERROR: PERMISSION DENIED", "User "+ str(current_user) + " tried to acess logs")
			return Result(error=True, message="Only ADMIN should get logs, this will be reported")
		
		try:
			self.cursor.execute("SELECT * FROM Logs")
			logs = self.cursor.fetchall()
			return Result(error=False, value=logs)
		except sqlite3.Error as e:
			print("Error occurred:", e)
			return Result(error=True, message="SQL Error occurred while getting logs")
		
	def get_commission_members(self, current_user: int, Commission_id: int) -> Result:
		"""
		Retrives the users of a Commission

		:param Commission_id: The ID of the Commission
		:return: Result object containing the users if successful, otherwise an error message.
		"""
		if not self.check_if_exists("Commission_members", "Id_commission", Commission_id):
			return Result(error=True, message="Commission " + str(Commission_id) + " does not exist")
		
		aux = self.get_role(current_user)
		if aux.is_err():
			return aux
		if aux.unwrap() not in ["ADMIN", "USER"]:
			return Result(error=True, message="Only ADMIN and USER should get Commission members")
		
		try:
			self.cursor.execute("SELECT * FROM Commission_members WHERE Id_commission = ?", (Commission_id,))
			members = self.cursor.fetchall()
			return Result(error=False, value=members)
		except sqlite3.Error as e:
			print("Error occurred:", e)
			return Result(error=True, message="SQL Error occurred while getting Commission members")
		
		




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
		#save private keys to keys directory

		new_file = open("keys/private_key_user2.pem", "w")
		new_file.write(private_key)
		new_file.close()

		self.assertTrue(self.db.create_user(1, "user2", public_key, "USER").unwrap())

	def test_add_candidate(self):
		self.assertTrue(self.db.add_candidate(1, "candidate1").unwrap())
		self.assertTrue(self.db.add_candidate(1, "candidate2").unwrap())


	
	def test_error_create_user(self):
		try: 
			aux = self.db.create_user(2, "user1", "pubkey1", "USER").unwrap()
			print(aux)
			self.assertFalse(aux)

		except:
			print("Expected error")
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

		#Create a mock election with sql statements
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
			print("Expected error")
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
			print("Error occurred")
			self.assertTrue(False)


	def test_get_elections(self):
		# Test get_elections for a user in commission 1
		result = self.db.get_elections(3)
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
	print(r'WARNING THIS WILL DELETE ALL DATA IN THE DATABASE')
	I = input('Are you sure? (y/n): ')
	if I != 'y':
		print('Aborted')
		return
	
	print("Running tests")
	
	dbtest = DatabaseTest()
	dbtest.setUp()
	
	dbtest.test_get_role()
	dbtest.test_create_user()
	dbtest.test_add_candidate()
	dbtest.test_error_create_user()
	dbtest.test_create_election()
	dbtest.test_vote()
	dbtest.test_vote_again()
	dbtest.test_get_votes()
	dbtest.test_get_logs()
	dbtest.test_get_elections()
	dbtest.tearDown()
	print("All tests passed!")
	
#test_db()
