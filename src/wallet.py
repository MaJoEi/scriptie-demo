import rsa
import crypto


class Wallet:
    crypto = crypto.Crypto()
    crypto.generateKeys()
    publicKey, privateKey = crypto.load_keys()

