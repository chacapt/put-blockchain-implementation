import rsa
from classes.Blockchain import Blockchain
from classes.User import User
from classes.Block import Block
from classes.Transaction import Transaction


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