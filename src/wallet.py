import os
import pickle
import threading
from utils import rsa_crypto, rsa_crypto2, ssi_util
from utils.client import Client
from pathlib import Path
from Cryptodome.PublicKey import RSA


class Wallet(Client):

    directory = os.path.dirname(__file__)

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.id = 'wallet'
        rsa_crypto2.generate_new_key_pair(self.id)
        self.__private_key = Path(f'{self.directory}/utils/keys/{self.id}private.pem')
        self.public_key = Path(Path(f'{self.directory}/utils/keys/{self.id}public.pem'))
        self.public_did = ssi_util.create_random_did()
        self.server_pub_key = None

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
    This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """
    def mock_session_establishment(self, port):
        self.establish_connection(port)


    def run(self):
        self.mock_session_establishment(13374)
