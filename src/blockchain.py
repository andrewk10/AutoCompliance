#!/usr/bin/python3

# Author: @andrewk10

# This code is the blockchain implementation for AutoCompliance

# Importing datetime for timestamps.
import datetime
# Importing strings for use of the external strings resources.
# import strings
# Importing strings_functions for string building functions.
# import strings_functions


class Blockchain:
    """
    This class defines the blockchain for AutoCompliance.
    """
    def __init__(self):
        # The blockchain itself.
        self.chain = []
        # Adds the first block to the chain.
        self.create_blockchain(proof=1, previous_hash='0')
        self.number_of_validators = 0
        self.consensus_context = 0
        self.speaker_timeout = 0
        self.validator = 0
        # Set to seconds
        self.block_time = 15

    def create_blockchain(self, proof, previous_hash):
        block = {
           "index": len(self.chain) + 1,
           "timestamp": str(datetime.datetime.now()),
           "proof": proof,
           "previous_hash": previous_hash
        }

        self.chain.append(block)
        return block

    def get_previous_block(self):
        last_block = self.chain[-1]
        return last_block

    def set_speaker_timeout(self):
        self.speaker_timeout = pow(2, self.chain.index(self.validator) + 1) * \
                               self.speaker_timeout

    def set_validator(self):
        self.validator = (self.chain.__len__() -
                          self.chain.index(self.validator)) % \
                         self.number_of_validators

    def initialise_consensus_information(self):
        self.consensus_context = self.number_of_validators - \
                                 ((self.number_of_validators-1)/3)
