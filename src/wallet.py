import rsa
import crypto


class Wallet:

    crypto.generateKeys()
    publicKey, privateKey = crypto.loadKeys()

