import binascii
import rsa
import uuid
import hashlib
import os
import pickle
import time

# Parameters
keyLength = 1024  # Do not change!!!
numberOfZeros = 5  # Number of zeros in proof of work


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
        self.public_key, self.private_key = rsa.newkeys(keyLength)

    def sign(self, transaction):
        transaction.signature = binascii.hexlify(
            rsa.sign(
                str(transaction).encode('ascii'), self.private_key,
                'SHA-256')).decode('ascii')


class Transaction:

    def __init__(self, sender: User, receiver: User, amount: float):
        self.id = uuid.uuid1()
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = b'0'
        self.sign_transaction()

    def __str__(self):
        return f"Id: {self.id}\n{self.sender} -> {self.receiver}: {self.amount}"

    def sign_transaction(self):
        self.sender.sign(self)


class Block:

    def __init__(self, transactions, prev_hash):
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.proof_of_work = 0
        self.hash = self.calc_hash()

    def __str__(self):
        tmp = f"Hash: {self.hash}\nTransactions ------\n\n"
        for x in self.transactions:
            tmp += f"{str(x)}\n"
            tmp += f"Signature: {x.signature}\n\n"
        tmp += f"End Transactions ------\nProof of work: {self.proof_of_work}"
        return tmp

    def calc_hash(self):
        temp = str(self.prev_hash)
        for x in self.transactions:
            temp += str(x)
        temp += str(self.proof_of_work)
        return hashlib.sha256(temp.encode()).hexdigest()

    def add_transaction(self, transaction: Transaction):
        self.transactions.append(transaction)
        self.hash = self.calc_hash()

    def calculate_proof_of_work(self):
        while not self.hash.startswith("0" * numberOfZeros):
            self.proof_of_work += 1
            self.hash = self.calc_hash()


class Blockchain:

    def __init__(self):
        self.chain = [self.create_init_block()]

    def create_init_block(self):
        return Block([], 0)

    def add_block(self, new_block: Block):
        new_block.prev_hash = self.chain[-1].hash
        new_block.calculate_proof_of_work()
        self.chain.append(new_block)
        return new_block.hash

    def get_hash(self):
        return self.chain[-1].hash

    def remove_blockchain(self):
        self = Blockchain()


class NetworkNodes:

    def __init__(self, blockchain: Blockchain, users):
        self.blockchain = blockchain
        self.users = users

    def get_user(self, name) -> rsa.PublicKey:
        return next((user.public_key for user in self.users if user.name == name))

    def verify_transaction(self, transaction: Transaction):
        try:
            return rsa.verify(
                str(transaction).encode('ascii'), transaction.signature,
                self.get_user(transaction.sender)) == 'SHA-256'
        except Exception:
            return False

    def verify_block(self, block: Block):
        for tx in block.transactions:
            if not self.verify_transaction(tx):
                return False
        if block.calc_hash() == block.hash:
            return True


def initialize_user_list():
    users = [(User("Adam", '123'))]
    users.append(User("Monika", '321'))

    return users


def print_all_blocks(block_list: Blockchain):
    for x in block_list.chain:
        print("\nBlock ---------------------------------------------")
        print(x)
        print("End block ---------------------------------------------")


def sing_up(network: NetworkNodes):
    name = input("Enter username: ")
    pwd_hash = ''
    while 1:
        password = input("Enter password: ")
        conf_password = input("Confirm password: ")
        if conf_password == password:
            pwd_hash = hashlib.md5(conf_password.encode()).hexdigest()
            break
        else:
            sing_up_error_msg("Passwords are not the same!")
    while 1:
        if network.get_user(name):
            network.users.append(User(name, pwd_hash))
            sing_up_error_msg("You have registered successfully!")
            break
        else:
            print("Name is taken, please enter again!")
            name = input("Enter username: ")


def sing_up_error_msg(arg0):
    print(arg0)
    time.sleep(2)
    os.system('cls')


def login(network: NetworkNodes):
    user = User('', '')
    while 1:
        name = input("Enter username: ")
        password = input("Enter password: ")
        pwd_hash = pwd_hash = hashlib.md5(password.encode()).hexdigest()

        if [user for user in network.users if user.name == name]:
            if user.token == pwd_hash:
                print("Welcome again!")
                break
        else:
            print("User does not exist or given password is wrong! \n")
            if input("Do you want to exit? (yes/no): ") == 'yes':
                break


def load_blockchain_network():
    blockchain_file = "blockchain.pkl"
    users_file = "users.pkl"
    if os.path.exists(blockchain_file):
        with open(blockchain_file, "rb") as file:
            blockchain = pickle.load(file)
    else:
        blockchain = Blockchain()

    if os.path.exists(users_file):
        with open(users_file, "rb") as file:
            users = pickle.load(file)
    else:
        users = []
    return (blockchain, users)


if __name__ == "__main__":
    users, blockchain = load_blockchain_network()
    blockchain_network = NetworkNodes(users, blockchain)
    while 1:
        print("********** Login System **********")
        print("1.Create new account")
        print("2.Login")
        print("3.Exit")
        choice = int(input("Enter your choice: "))

        match choice:
            case 1:
                sing_up(blockchain_network)
            case 2:
                login(blockchain_network)
            case 3:
                break
            case _:
                print("Wrong Choice!")
        os.system('cls')
