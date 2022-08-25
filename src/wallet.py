import os
import pickle
import threading
from utils import rsa_crypto, ssi_util, rsa_crypto2
from utils.client import Client
from pathlib import Path


class Wallet(Client):

    directory = os.path.dirname(__file__)

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        #rsa_crypto.generateKeys()
        # self.__privateKey, self.publicKey = rsa_crypto.loadKeys()
        self.id = 'wallet'
        rsa_crypto2.generate_new_key_pair(self.id)
        filename = os.path.join(self.directory, 'utils', 'keys', f'{self.id}private.pem')
        self.__private_key = Path(filename)
        filename = os.path.join(self.directory, 'utils', 'keys', f'{self.id}public.pem')
        self.public_key = Path(filename)
        # self.public_did = ssi_util.create_random_did()
        self.server_pub_key = None
        # self.key_id, self.__privateKey, self.publicKey = ssi_util.create_and_export_keypair()
        # print(self.__privateKey)
        # print(self.publicKey)

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
    This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """
    def mock_session_establishment(self, port):
        self.establish_connection(port)
        msg1 = self.receive()
        self.server_pub_key, signature = pickle.loads(msg1)
        print(self.server_pub_key)
        print(signature)
        if not rsa_crypto.verify_bytes(msg1, signature, self.server_pub_key):
            print("Faulty signature")
            self.interrupt_connection()
            return
        print("Signature checks out")
        #  nonce, ciphertext, tag, encrypted_aes_key = rsa_crypto.encrypt_large_message(self.publicKey,server_pub_key)
        # message = rsa_crypto.encrypt(pickle.dumps(self.publicKey), server_pub_key)
        # msg2 = pickle.dumps({nonce, ciphertext, tag, encrypted_aes_key},4)
        # self.send(msg2)
        # resp = self.receive()

    def run(self):
        self.mock_session_establishment(13374)
