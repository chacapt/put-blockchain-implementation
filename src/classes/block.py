import binascii
import hashlib
import os
from classes.Transaction import Transaction


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
        while not self.hash.startswith("0" * int(os.getenv("POC_ZEROS", 1024))):
            self.proof_of_work += 1
            self.hash = self.calc_hash()