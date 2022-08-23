from utils import rsa_crypto, ssi_util
from utils.server import Server


class Verifier(Server):
    rsa_crypto.generateKeys()
    __privateKey, publicKey = rsa_crypto.loadKeys()
    public_did = ssi_util.create_did()

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def session_establishment(self):
        pass
