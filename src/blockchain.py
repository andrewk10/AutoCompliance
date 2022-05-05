#!/usr/bin/python3

# Author: @andrewk10

# This code is the blockchain implementation for AutoCompliance

# Using flask to send messages to postman.
from flask import Flask, jsonify
# Importing datetime for timestamps.
import datetime
# Importing json to encode information as JSON.
import json
# Hashlib for the hashing of blockchain blocks.
import hashlib


class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_blockchain(proof=1, previous_hash='0')

    def create_blockchain(self, proof, previous_hash):
        block = {
           'index': len(self.chain) + 1,
           'timestamp': str(datetime.datetime.now()),
           'proof': proof,
           'previous_hash': previous_hash
        }

        self.chain.append(block)
        return block

    def get_previous_block(self):
        last_block = self.chain[-1]
        return last_block


app = Flask(__name__)
blockchain = Blockchain()


@app.route('/get_proof', methods=['GET'])
def delegated_byzantine_fault_tolerance(previous_proof):
    new_proof = 1
    check_proof = False
    while check_proof is False:
        hash_operation = hashlib.sha256(str(
            new_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
        if hash_operation[:4] == '0000':
            check_proof = True
        else:
            new_proof += 1
    return new_proof


@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200


@app.route('/get_hash_block', methods=['GET'])
def hash_block(block):
    encoded_block = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(encoded_block).hexdigest()


@app.route('/chain_valid', methods=['GET'])
def is_chain_valid(chain):
    previous_block = chain[0]
    block_index = 1
    while block_index < len(chain):
        block = chain[block_index]
        if block["previous_hash"] != hash(previous_block):
            return False

        previous_proof = previous_block['proof']

        current_proof = block['proof']

        hash_operation = hashlib.sha256(str(
            current_proof ** 2 - previous_proof ** 2).encode()).hexdigest()
        if hash_operation[:4] != '0000':
            return False
        previous_block = block
        block_index += 1
    return True


@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = delegated_byzantine_fault_tolerance(previous_proof)
    previous_hash = hash(previous_block)

    block = blockchain.create_blockchain(proof, previous_hash)
    response = {'message': 'Block mined!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash']}
    return jsonify(response), 200


app.run(host='127.0.0.1', port=5000)
