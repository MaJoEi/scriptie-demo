import pickle
import threading
from utils import rsa_crypto, ssi_util
from utils.server import Server


class Verifier(Server):

    def __init__(self, port, threadID):
        threading.Thread.__init__(self)
        self.port = port
        self.threadID = threadID
        self.s.bind((self.host, port))
        rsa_crypto.generateKeys()
        self.__privateKey, self.publicKey = rsa_crypto.loadKeys()
        self.public_did = ssi_util.create_random_did()

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def mock_session_establishment(self):
        self.establish_connection()
        msg1 = pickle.dumps(self.publicKey, 1)
        self.send(msg1)
        msg2 = self.receive()
        client_pub_key = rsa_crypto.decrypt(msg1)
        print(client_pub_key)

    def run(self):
        self.mock_session_establishment()
