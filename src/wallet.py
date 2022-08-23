import requests
import rsa_crypto
import ssi_util


class Wallet:
    rsa_crypto.generateKeys()
    __privateKey, publicKey = rsa_crypto.loadKeys()

    # Mocked session establishment where wallet and verifier share identifiers and cryptographic keys
    def session_establishment(self, wallet_public_key):
        pass
