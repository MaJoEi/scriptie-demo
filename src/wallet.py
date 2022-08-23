import threading
from utils import rsa_crypto, ssi_util
from utils.client import Client


class Wallet(Client):
    # rsa_crypto.generateKeys()
    # __privateKey, publicKey = rsa_crypto.loadKeys()
    # public_did = ssi_util.create_did()

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def session_establishment(self):
        pass
