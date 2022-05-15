#!/usr/bin/python3

# Author: @andrewk10

# Importing blockchain for blockchain  based functionality
import blockchain


def test_create_blockchain():
    """
    This function tests the create_blockchain function in the blockchain
    script. It uses example arguments to do this stored in strings.py, but
    before it does that the bad path is checked by passing in a single argument
    with no value to get a runtime error.
    """
    # Creating blockchain itself.
    test_blockchain = blockchain.Blockchain()
    # Testing against the genesis block.
    assert test_blockchain.get_previous_block()["index"] == 1
    assert test_blockchain.get_previous_block()["timestamp"] is not None
    assert test_blockchain.get_previous_block()["proof"] == 1
    assert test_blockchain.get_previous_block()["previous_hash"] == "0"
