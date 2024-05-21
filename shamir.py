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
            raise Exception("Invalid arguments")



    def first_init(self, num_members: int, secret: bytes, bits: int = 128):
        if bits < 128:
            raise Exception("Bits must be greater than or equal to 128")
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
        if self.secret_sharing_scheme == []: 
            self.fuction = [self.secret] + [random.randint(1, self.prime - 1) for _ in range(self.num_members - 1)]          
            for _ in range(0, self.num_members):
                x = random.randint(1, self.prime - 1) 
                share = sum(coeff * x ** i for i, coeff in enumerate(self.fuction)) % self.prime
                self.secret_sharing_scheme.append((x, share))

    def recuperate_secret(self):
        x = 0
        for j in range(0, len(self.secret_sharing_scheme)):
           l_j = 1
           for i in range(0, len(self.secret_sharing_scheme)):
                if i == j:
                    continue

                l_j *= (-self.secret_sharing_scheme[i][0]) *  mod_inverse(self.secret_sharing_scheme[j][0] - self.secret_sharing_scheme[i][0], self.prime) 

           x += (l_j * self.secret_sharing_scheme[j][1])

        print("Secret: " + str(hex(x % self.prime)))
        self.secret = hex(x % self.prime)[2:]


def main():

    string = ""
    for _ in range(0, 256):
        string += "a"
    string = bytes(string, 'utf-8')
    print("String len: " + str(len(str(int(string.hex(), 16)))))

    test1 = Shamir(3, string, 2048)
    print("Test 1: " + str(test1.secret_sharing_scheme))

    test2 = Shamir(test1.secret_sharing_scheme, test1.prime)
    print("Test 2: " + str(test2.secret))
    print("Test 2: " + str(test2.secret==string.decode("utf-8")))
#if __name__ == "__main__":
    #main()

