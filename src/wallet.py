import threading
from utils import rsa_crypto, ssi_util
from utils.client import Client


class Wallet(Client):
    # rsa_crypto.generateKeys()
    # __privateKey, publicKey = rsa_crypto.loadKeys()

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.key_id, self.__privateKey, self.publicKey = ssi_util.create_and_export_keypair()
        print(self.__privateKey)
        print(self.publicKey)

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def session_establishment(self, port):
        self.establish_connection(port)

        pass
