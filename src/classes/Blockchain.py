from classes.Block import Block

class Blockchain:

    def __init__(self):
        self.chain = [self.create_init_block()]

    def __str__(self):
        tmp = ''
        for x in self.chain:
            tmp += "\nBlock ---------------------------------------------"  # delete later
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