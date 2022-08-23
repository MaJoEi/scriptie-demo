import threading
from utils import rsa_crypto, ssi_util
from utils.server import Server


class Verifier(Server):
    # rsa_crypto.generateKeys()
    # __privateKey, publicKey = rsa_crypto.loadKeys()
    # public_did = ssi_util.create_did()

    def __init__(self, port, threadID):
        threading.Thread.__init__(self)
        self.port = port
        self.threadID = threadID
        self.s.bind((self.host, port))

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def session_establishment(self):
        pass
