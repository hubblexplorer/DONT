import random
from sympy import mod_inverse
from Crypto.Util import number

class Shamir:
    def __init__(self, *args):
        if len(args) == 2 and type(args[0]) == list and type(args[1]) == int:
            self.reconstruct_init(args[0], args[1])
        elif len(args) == 2 and type(args[0]) == int and type(args[1]) == bytes:
            self.first_init(args[0], args[1])
        elif len(args) == 3 and type(args[0]) == int and type(args[1]) == bytes and type(args[2]) == int:
            self.first_init(args[0], args[1], args[2])
        else:
            raise Exception("Argumentos inválidos")

    def first_init(self, num_members: int, secret: bytes, bits: int = 128):
        if bits < 128:
            raise Exception("O número de bits deve ser maior ou igual a 128")
        self.num_members = num_members
        self.secret_sharing_scheme = []
        self.fuction = None
        self.prime = number.getPrime(bits)
        self.secret = int(secret.hex(), 16)
        self.generate_secret_sharing_scheme()

    def reconstruct_init(self, secrets: list, prime: int):
        self.num_members = len(secrets)
        self.secret_sharing_scheme = secrets
        self.fuction = []
        self.prime = prime
        self.recuperate_secret()

    def generate_secret_sharing_scheme(self):
        if not self.secret_sharing_scheme: 
            self.fuction = [self.secret] + [random.randint(1, self.prime - 1) for _ in range(self.num_members - 1)]          
            for _ in range(self.num_members):
                x = random.randint(1, self.prime - 1) 
                share = sum(coeff * x ** i for i, coeff in enumerate(self.fuction)) % self.prime
                self.secret_sharing_scheme.append((x, share))

    def recuperate_secret(self):
        x = 0
        for j in range(len(self.secret_sharing_scheme)):
           l_j = 1
           for i in range(len(self.secret_sharing_scheme)):
                if i == j:
                    continue
                l_j *= (-self.secret_sharing_scheme[i][0]) * mod_inverse(self.secret_sharing_scheme[j][0] - self.secret_sharing_scheme[i][0], self.prime)
           x += (l_j * self.secret_sharing_scheme[j][1])

        print("Segredo: " + str(hex(x % self.prime)))
        self.secret = hex(x % self.prime)[2:]

def main():
    string = ""
    for _ in range(256):
        string += "a"
    string = bytes(string, 'utf-8')
    print("Comprimento da string: " + str(len(str(int(string.hex(), 16)))))

    teste1 = Shamir(3, string, 2048)
    print("Teste 1: " + str(teste1.secret_sharing_scheme))

    teste2 = Shamir(teste1.secret_sharing_scheme, teste1.prime)
    print("Teste 2: " + str(teste2.secret))
    print("Teste 2: " + str(teste2.secret == string.decode("utf-8")))

#if __name__ == "__main__":
    #main()
