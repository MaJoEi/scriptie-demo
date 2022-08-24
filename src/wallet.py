import pickle
import threading
import rsa

from utils import rsa_crypto, ssi_util
from utils.client import Client


class Wallet(Client):

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        rsa_crypto.generateKeys()
        self.__privateKey, self.publicKey = rsa_crypto.loadKeys()
        self.public_did = ssi_util.create_random_did()
        # self.key_id, self.__privateKey, self.publicKey = ssi_util.create_and_export_keypair()
        # print(self.__privateKey)
        # print(self.publicKey)

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
    This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """
    def mock_session_establishment(self, port):
        self.establish_connection(port)
        msg1 = self.receive()
        server_pub_key = pickle.loads(msg1)
        nonce, ciphertext, tag, encrypted_aes_key = rsa_crypto.encrypt_large_message(self.publicKey,server_pub_key)
        # message = rsa_crypto.encrypt(pickle.dumps(self.publicKey), server_pub_key)
        msg2 = pickle.dumps({nonce, ciphertext, tag, encrypted_aes_key},4)
        self.send(msg2)
        # resp = self.receive()

    def run(self):
        self.mock_session_establishment(13374,)
