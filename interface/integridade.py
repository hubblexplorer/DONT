import tkinter as tk
from tkinter import messagebox
import hashlib
import sys
import os
# Adicionar o diretório pai ao caminho de pesquisa de módulos do Python
current_dir = os.path.dirname(__file__)
parent_dir = os.path.abspath(os.path.join(current_dir, '..'))
sys.path.append(parent_dir)
from api.api_db import Database

def verify_hmac(vote, hmac, key):
    """Verify the HMAC-SHA512 integrity of a vote."""
    computed_hmac = hashlib.sha512(f"{vote}{key}".encode()).hexdigest()
    return hmac == computed_hmac

def show_results(results):
    results_window = tk.Toplevel(root)
    results_window.title("Verification Results")
    
    for i, result in enumerate(results):
        vote, hmac, key, is_valid = result
        status = "Valid" if is_valid else "Invalid"
        result_label = tk.Label(results_window, text=f"Vote: {vote}, HMAC: {hmac}, Key: {key}, Status: {status}")
        result_label.pack()

def verify_votes():
    current_user = entry_user_id.get()
    election_id = entry_election_id.get()
    
    try:
        current_user = int(current_user)
        election_id = int(election_id)
    except ValueError:
        messagebox.showerror("Input Error", "User ID and Election ID must be integers")
        return
    
    result = Database.get_votes(current_user, election_id)
    
    if result.error:
        messagebox.showerror("Error", result.message)
        return
    
    votes = result.value
    verification_results = []
    
    for vote in votes:
        vote_data, hmac, key = vote
        is_valid = verify_hmac(vote_data, hmac, key)
        verification_results.append((vote_data, hmac, key, is_valid))
    
    show_results(verification_results)

# Criação da interface Tkinter
root = tk.Tk()
root.title("Vote Integrity Verification")

label_user_id = tk.Label(root, text="Current User ID:")
label_user_id.pack()
entry_user_id = tk.Entry(root)
entry_user_id.pack()

label_election_id = tk.Label(root, text="Election ID:")
label_election_id.pack()
entry_election_id = tk.Entry(root)
entry_election_id.pack()

verify_button = tk.Button(root, text="Verify Votes", command=verify_votes)
verify_button.pack()

root.mainloop()
