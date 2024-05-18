import pyperclip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox

def load_private_key(filepath):
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(filepath):
    with open(filepath, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def sign_challenge(private_key, challenge):
    print(challenge)
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, challenge, signature):
    try:
        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def main():
    # Janela para seleção de arquivo de chave privada
    root = tk.Tk()
    root.withdraw()
    private_key_path = filedialog.askopenfilename(
        title="Selecione sua chave privada",
        filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
    )

    if not private_key_path:
        messagebox.showerror("Erro", "Nenhum arquivo de chave privada selecionado.")
        return

    try:
        private_key = load_private_key(private_key_path)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao carregar chave privada: {e}")
        return

    # Obter o desafio da área de transferência
    challenge_hex = pyperclip.paste().strip()
    try:
        challenge = bytes.fromhex(challenge_hex)
    except ValueError:
        messagebox.showerror("Erro", "Desafio inválido. Certifique-se de que o desafio copiado está em formato hexadecimal.")
        return

    try:
        signature = sign_challenge(private_key, challenge)
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao assinar o desafio: {e}")
        return

    signature_hex = signature.hex()

    # Exibir a assinatura para o usuário
    signature_window = tk.Tk()
    signature_window.title("Assinatura Gerada")
    
    label = tk.Label(signature_window, text="Assinatura (copie e cole na aplicação):")
    label.pack(padx=10, pady=10)
    
    signature_text = tk.Text(signature_window, height=10, width=50)
    signature_text.pack(padx=10, pady=10)
    signature_text.insert(tk.END, signature_hex)
    
    copy_button = tk.Button(signature_window, text="Copiar Assinatura", command=lambda: pyperclip.copy(signature_hex))
    copy_button.pack(padx=10, pady=10)
    
    def verify_signature_callback():
        # Janela para seleção de arquivo de chave pública
        public_key_path = filedialog.askopenfilename(
            title="Selecione sua chave pública",
            filetypes=(("PEM files", "*.pem"), ("All files", "*.*"))
        )
        
        if not public_key_path:
            messagebox.showerror("Erro", "Nenhum arquivo de chave pública selecionado.")
            return
        
        try:
            public_key = load_public_key(public_key_path)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao carregar chave pública: {e}")
            return

        signature = bytes.fromhex(signature_text.get("1.0", "end").strip())
        if verify_signature(public_key, challenge, signature):
            messagebox.showinfo("Sucesso", "A assinatura é válida!")
        else:
            messagebox.showerror("Erro", "A assinatura não é válida.")

    verify_button = tk.Button(signature_window, text="Verificar Assinatura", command=verify_signature_callback)
    verify_button.pack(padx=10, pady=10)
    
    signature_window.mainloop()

if __name__ == "__main__":
    main()
