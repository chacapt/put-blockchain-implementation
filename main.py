import binascii
import rsa
import uuid
import hashlib

# Parameters
keyLength = 1024  # Do not change!!!
numberOfZeros = 5  # Number of zeros in proof of work


class User:

    def __init__(self, name: str, password):
        self.name = name
        self.token = hashlib.sha256(password.encode()).hexdigest()
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

    def verify(self, transaction):
        try:
            return rsa.verify(
                str(transaction).encode('ascii'), transaction.signature,
                self.public_key) == 'SHA-256'
        except Exception:
            return False


class Transaction:

    def __init__(self, sender: User, receiver: User, amount: float):
        self.id = uuid.uuid1()
        self.sender = sender
        self.receiver = receiver
        self.amount = amount
        self.signature = 0

    def __str__(self):
        return f"Id: {self.id}\n{self.sender} -> {self.receiver}: {self.amount}"

    def sign_transaction(self):
        self.signature = self.sender.sign(self)


class Block:

    def __init__(self, transactions, prev_hash):
        self.prev_hash = prev_hash
        self.transactions = transactions
        self.proof_of_work = 0
        self.hash = self.calc_hash()

    def __str__(self):
        tmp = f"Hash: {self.prev_hash}\nTransactions ------\n\n"
        for x in self.transactions:
            tmp += f"{str(x)}\n"
            tmp += f"Signature: {x.signature}\n\n"
        tmp += f"End Transactions ------\nProof of work: {self.proof_of_work}"
        return tmp

    def calc_hash(self):
        return hashlib.sha256(str(self).encode()).hexdigest()

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


    public_key, private_key = rsa.newkeys(keyLength)
    users.append(User("Monika", private_key, public_key))

    return users


def initialize_block_list():
    return [Block([], 0)]


def get_hash_of_block(block: Block):
    return hashlib.sha256(str(block).encode()).hexdigest()


def add_transaction(block: Block, sender: User, receiver: User, amount: float):
    transaction = Transaction(sender, receiver, amount)
    sender.sign(transaction)
    block.add_transaction(transaction)


def create_new_block(block: Block, block_list):
    calculate_proof_of_work(block)
    # new_block = Block(get_hash_of_block(block))
    # block_list.append(new_block)
    # return new_block


def print_all_blocks(block_list):
    for x in block_list:
        print("\nBlock ---------------------------------------------")
        print(x)
        print("End block ---------------------------------------------")


if __name__ == "__main__":
    users = initialize_user_list()
    blocks = initialize_block_list()
    current_last_block = blocks[0]

    # add_transaction(current_last_block, users[0], users[1], 10)
    # add_transaction(current_last_block, users[1], users[0], 100)

    current_last_block = create_new_block(current_last_block, blocks)
    # add_transaction(current_last_block, users[0], users[1], 10)
    calculate_proof_of_work(blocks[0])
    print_all_blocks(blocks)
