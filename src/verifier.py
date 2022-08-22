import rsa
import crypto


class Verifier:
    crypto = crypto
    crypto.generateKeys()
    publicKey, privateKey = crypto.loadKeys()
