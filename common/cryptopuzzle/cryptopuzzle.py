import os
import sys
from random import randint
import random
import time
from Crypto.Hash import SHA256

'''
    Override __getitem__ from dict to delete keys that are expired
'''
class ExpiringDict(dict):
    def __init__(self, *args):
        dict.__init__(self, args)

    def __getitem__(self, key):
        '''
            Delete key if already expired
        '''
        actual_time = time.time()
        val = dict.__getitem__(self, key)
        if (val[1] < actual_time):
            self.pop('key', None)
            return None
        return val

class CryptoPuzzle:

    # Saves puzzles sent to clients
    sent_puzzles = ExpiringDict()

    def create_puzzle(self, public_key):
        '''
            Creates puzzle to solve

            inputs:
                public_key - public key of user that will solve the puzzle
            output:
                puzzle - hashed result of public_key xor random value
                starts_with - beggining of random value used on hash function
                ends_with - ending of random value used on hash function

            There are 2 bytes left between starts_with and ends_with that the
                user needs to find out using brute force
        '''
        solution = os.urandom( len(public_key) )
        plain = self.string_xor(public_key, solution)
        puzzle = SHA256.new(data=plain).hexdigest()

        starts_with_index = randint(0, int( len(public_key) * random.uniform(0, 1) ) )
        ends_with_index = starts_with_index + 2

        starts_with = solution[:starts_with_index]
        ends_with = solution[ends_with_index:]

        self.sent_puzzles[public_key] = (puzzle, time.time() + 60)

        return puzzle, starts_with, ends_with

    def validate_solution(self, public_key, solution):
        '''
            Validates possible solution, also returns false if the puzzle is expired (60 seconds)
        '''
        return self.sent_puzzles[public_key][0] == SHA256.new( data= self.string_xor(public_key, solution) ).hexdigest()

    def solve_puzzle(self, puzzle, public_key, starts_with, ends_with):
        '''
            Try to solve puzzle (user side)
        '''
        attempt = self.build_attempt(starts_with, ends_with)
        while (puzzle != SHA256.new( data= self.string_xor(public_key, attempt) ).hexdigest()):
            attempt = self.build_attempt(starts_with, ends_with)
        return attempt

    def build_attempt(self, starts_with, ends_with):
        '''
            Build an attempt of a solution
        '''
        return starts_with + os.urandom(2) + ends_with

    def string_xor(self, stringA, stringB):
        '''
            XOR between 2 bytes string
        '''
        return bytes(x ^ y for x, y in zip(stringA, stringB))
