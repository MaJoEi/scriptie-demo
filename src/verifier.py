import os
import pickle
import threading
from utils import rsa_crypto, ssi_util, rsa_crypto2
from utils.server import Server
from pathlib import Path


class Verifier(Server):

    directory = os.path.dirname(__file__)

    def __init__(self, port, threadID):
        threading.Thread.__init__(self)
        self.port = port
        self.threadID = threadID
        self.s.bind((self.host, port))
        self.id = f'verifier{port}'
        #rsa_crypto.generateKeys()
        #self.__privateKey, self.publicKey = rsa_crypto.loadKeys()
        rsa_crypto2.generate_new_key_pair(self.id)
        filename = os.path.join(self.directory, 'utils', 'keys', f'{self.id}private.pem')
        self.__private_key = Path(filename)
        filename = os.path.join(self.directory, 'utils', 'keys', f'{self.id}public.pem')
        self.public_key = Path(filename)
        self.public_did = ssi_util.create_random_did()

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def mock_session_establishment(self):
        self.establish_connection()
        msg1_signature = rsa_crypto.sign_bytes(pickle.dumps(self.public_key, 1), self.__private_key)
        print(self.public_key)
        print(msg1_signature)
        msg1 = pickle.dumps({self.public_key, msg1_signature}, 2)
        self.send(msg1)
        msg2 = self.receive()
        client_pub_key = rsa_crypto.decrypt(msg1)
        print(client_pub_key)

    def run(self):
        self.mock_session_establishment()
