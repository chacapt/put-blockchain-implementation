import rsa
import os


class User:

    def __init__(self, name: str, pwd_hash):
        self.name = name
        self.token = pwd_hash
        self.public_key: rsa.PublicKey
        self.private_key: rsa.PrivateKey
        self.__generate_key_pair()

    def __str__(self):
        return f"{self.name}"

    def __generate_key_pair(self):
        self.public_key, self.private_key = rsa.newkeys(int(os.getenv("RSA_KEY_SIZE", 1024)))

    def sign(self, transaction):
        transaction.signature = rsa.sign(
            str(transaction).encode('ascii'), self.private_key, 'SHA-256')