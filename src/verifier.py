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
        rsa_crypto2.generate_new_key_pair(self.id)
        self.__private_key = Path(f'{self.directory}/utils/keys/{self.id}private.pem')
        self.public_key = Path(Path(f'{self.directory}/utils/keys/{self.id}public.pem'))
        self.public_did = ssi_util.create_random_did()
        self.client_pub_key = None

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def mock_session_establishment(self):
        self.establish_connection()
        

    def run(self):
        self.mock_session_establishment()
