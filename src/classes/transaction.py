from classes.User import User
import uuid


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