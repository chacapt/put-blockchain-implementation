import binascii
import rsa
import uuid
import hashlib
import os
import pickle
import time

# Parameters
keyLength = 1024  # Do not change!!!
numberOfZeros = 6  # Number of zeros in proof of work


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
        transaction.signature = rsa.sign(
            str(transaction).encode('ascii'), self.private_key, 'SHA-256')


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
        self.transactions = transactions[:]
        self.proof_of_work = 0
        self.hash = self.calc_hash()

    def __str__(self):
        tmp = f"\nHash: {self.hash}\nTransactions ------\n\n"
        for x in self.transactions:
            tmp += f"{str(x)}\n"
            tmp += f"Signature: {binascii.hexlify(x.signature).decode('ascii')}\n\n"
        tmp += f"End Transactions ------\nProof of work: {self.proof_of_work}\n"
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

    def __str__(self):
        tmp = ''
        for x in self.chain:
            tmp += "\nBlock ---------------------------------------------"
            tmp += str(x)
            tmp += "End block ---------------------------------------------"
        return tmp

    def create_init_block(self):
        return Block([], 0)

    def add_block(self, new_block: Block):
        new_block.prev_hash = self.chain[-1].hash
        new_block.calculate_proof_of_work()
        self.chain.append(new_block)

    def get_tail_hash(self):
        return self.chain[-1].hash


class NetworkNodes:

    def __init__(self, blockchain: Blockchain, users: list[User]):
        self.blockchain = blockchain
        self.users = users

    def get_userPubKey(self, sender: User) -> rsa.PublicKey:
        return next((user.public_key for user in self.users if user.name == sender.name))

    def find_user(self, name):
        try:
            next((user.public_key for user in self.users if user.name == name))
        except Exception:
            return False
        return True

    def verify_transaction(self, transaction: Transaction):
        try:
            return rsa.verify(
                str(transaction).encode('ascii'), transaction.signature,
                self.get_userPubKey(transaction.sender)) == 'SHA-256'
        except Exception:
            return False

    def verify_block(self, block: Block):
        for tx in block.transactions:
            if not self.verify_transaction(tx):
                return False
        if block.calc_hash() == block.hash:
            return True

    def mine_block(self, block: Block):
        self.blockchain.add_block(block)
        return self


def sing_up(network: NetworkNodes):
    os.system('cls')
    name = input("Enter username: ")
    pwd_hash = ''
    while 1:
        os.system('cls')
        print("Username: ", name)
        password = input("Enter password: ")
        conf_password = input("Confirm password: ")
        if conf_password == password:
            pwd_hash = hashlib.md5(conf_password.encode()).hexdigest()
            break
        else:
            sing_up_error_msg("Passwords are not the same!")

    while 1:
        if not network.find_user(name):
            network.users.append(User(name, pwd_hash))
            sing_up_error_msg("You have registered successfully!")
            users, blockchain = network.users, network.blockchain
            save_objects(blockchain, users)
            os.system('cls')
            break
        else:
            os.system('cls')
            print("Name is taken, please enter again!")
            name = input("Enter username: ")


def sing_up_error_msg(arg0):
    print(arg0)
    time.sleep(2)
    os.system('cls')


def login(network: NetworkNodes):
    user = User('', '')
    while 1:
        os.system('cls')
        name = input("Enter username: ")
        password = input("Enter password: ")
        user = next((u for u in network.users if u.name == name), None)
        if user != None:
            pwd_hash = hashlib.md5(password.encode()).hexdigest()
            if user.token == pwd_hash:
                os.system('cls')
                print("Welcome again!")
                time.sleep(0.4)
                return user
            else:
                print("User does not exist or given password is wrong! \n")
                if input("Do you wish to return? (yes/no): ").lower() == 'yes':
                    return None
        else:
            print("User does not exist or given password is wrong! \n")
            if input("Do you wish to return? (yes/no): ").lower() == 'yes':
                return None


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
        users: list[User] = []
    return (blockchain, users)


def login_menu(blockchain_network):
    while 1:
        print("********** Blockchain System Login  **********")
        print("1.Create new account")
        print("2.Login")
        print("3.Exit")
        choice = int(input("Enter your choice (1-3): "))

        match choice:
            case 1:
                sing_up(blockchain_network)
            case 2:
                user = login(blockchain_network)
                if user != None:
                    return user
            case 3:
                login_menu_msg("Exiting...")
                exit()
            case _:
                login_menu_msg("Wrong Choice!")
        os.system('cls')


def login_menu_msg(arg0):
    os.system('cls')
    print(arg0)
    time.sleep(0.7)
    os.system('cls')


def add_transaction(blockchain_network: NetworkNodes, currentUser: User):
    os.system('cls')
    print("----- List of recipients -----")
    user_list: list[User] = blockchain_network.users[:]
    for user in user_list:
        if user.name == currentUser.name:
            user_list.remove(user)
    for user in enumerate(user_list):
        if user[1].name != currentUser.name:
            print(user[0]+1, user[1].name)
    print("-----------------------------")
    choice = int(input("Pick position of the recipient: "))
    amount = float(input("Amount of the transaction: "))
    transaction = Transaction(
        currentUser, user_list[choice-1], amount)
    os.system('cls')
    print("Verifying new transaction...")
    time.sleep(0.8)
    if blockchain_network.verify_transaction(transaction):
        return transaction
    else:
        return None


def show_transactions(transactions: list[Transaction]):
    os.system('cls')
    print("----- List of non-mined transactions -----")
    for tx in transactions:
        print(tx)
    print("------------------------------------------")
    while 1:
        if input("Return? (yes/no): ").lower() == 'yes':
            os.system('cls')
            return


def mine_block(blockchain_network: NetworkNodes, transactions: list[Transaction]):
    os.system('cls')
    if not transactions:
        print("There are no transations!")
        time.sleep(0.6)
        return blockchain_network
    block = Block(transactions, blockchain_network.blockchain.get_tail_hash())
    print("Mining the new block...")
    blockchain_network_new: NetworkNodes = blockchain_network.mine_block(block)
    mine_msg("Block has been mined", 0.5)
    if blockchain_network.verify_block(blockchain_network_new.blockchain.chain[-1]):
        mine_msg("Block is being verified...", 0.5)
        mine_msg(
            "Block has been successfully verified and added to the Blockchain", 0.3)
        return blockchain_network_new
    else:
        mine_msg("Block could not be verified!", 0.5)


def mine_msg(arg0, arg1):
    os.system('cls')
    print(arg0)
    time.sleep(arg1)


def blockchain_user_menu(blockchain_network: NetworkNodes, user: User, transaction: list[Transaction]):
    os.system('cls')
    while 1:
        print("Currently logged as: ", user.name,
              "\t\tTransactions: ", len(transactions))
        print("---------    Blockchain User Interface   ---------")
        print("1. Show current blockchain")
        print("2. Add new transaction")
        print("3. Show transactions not in blockchain")
        print("4. Mine block of current transactions")
        print("5. Logout")
        choice = int(input("Enter your choice (1-5): "))

        match choice:
            case 1:
                os.system('cls')
                print(blockchain_network.blockchain)
                while 1:
                    if input("Return (yes/no): ").lower() == 'yes':
                        break
                os.system('cls')
            case 2:
                tx = add_transaction(blockchain_network, user)
                if tx != None:
                    transactions.append(tx)
                    print("Transaction has been successfully verified and added!")
                    time.sleep(0.7)
                else:
                    print("Transaction could not be verified!")
                    time.sleep(0.7)
            case 3:
                show_transactions(transactions)
            case 4:
                mine_block(blockchain_network, transactions)
                transactions.clear()
                os.system('cls')
            case 5:
                login_menu_msg("Logging out...")
                break
            case _:
                login_menu_msg("Wrong Choice!")
        os.system('cls')
    users, blockchain = blockchain_network.users, blockchain_network.blockchain
    save_objects(blockchain, users)
    return transactions


def save_objects(blockchain: Blockchain, users: list[User]):
    blockchain_file = "blockchain.pkl"
    users_file = "users.pkl"
    with open(blockchain_file, "wb") as file:
        pickle.dump(blockchain, file)

    with open(users_file, "wb") as file:
        pickle.dump(users, file)


if __name__ == "__main__":
    users, blockchain = load_blockchain_network()
    blockchain_network = NetworkNodes(users, blockchain)
    transactions: list[Transaction] = []
    while 1:
        logged_user = login_menu(blockchain_network)
        if logged_user != None:
            transactions = blockchain_user_menu(
                blockchain_network, logged_user, transactions)
