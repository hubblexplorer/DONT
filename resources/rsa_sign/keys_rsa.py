from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def generate_rsa_keypair():
    # Gerar uma chave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Obter a chave pública correspondente
    public_key = private_key.public_key()

    # Serializar a chave privada para o formato PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializar a chave pública para o formato PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Converter as chaves PEM em strings
    private_key_str = private_pem.decode('utf-8')
    public_key_str = public_pem.decode('utf-8')

    return private_key_str, public_key_str




def sign_message(private_key_str, message):
    # Carregar a chave privada
    private_key = serialization.load_pem_private_key(
        private_key_str.encode(),
        password=None,
        backend=default_backend()
    )

    # Assinar a mensagem
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

# Exemplo de uso:
private_key_str, public_key_str = generate_rsa_keypair()

print("Chave privada RSA:")
print(private_key_str)

print("\nChave pública RSA:")
print(public_key_str)

