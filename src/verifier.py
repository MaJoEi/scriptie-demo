import rsa
import crypto


class Verifier:
    crypto = crypto.Crypto()
    crypto.generateKeys()
    publicKey, privateKey = crypto.loadKeys()
