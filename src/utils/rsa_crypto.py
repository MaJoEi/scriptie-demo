import os
import rsa


def generateKeys():
    dir = os.path.dirname(__file__)
    (publicKey, __privateKey) = rsa.newkeys(1024)
    print(publicKey)
    print(__privateKey)
    filename = os.path.join(dir, 'keys', 'publicKey.pem')
    with open(filename, 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))
    filename = os.path.join(dir, 'keys', 'privateKey.pem')
    with open(filename, 'wb') as p:
        p.write(__privateKey.save_pkcs1('PEM'))


def loadKeys():
    dir = os.path.dirname(__file__)
    filename = os.path.join(dir, 'keys', 'publicKey.pem')
    with open(filename, 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    filename = os.path.join(dir, 'keys', 'privateKey.pem')
    with open(filename, 'rb') as p:
        __privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    print(publicKey)
    print(__privateKey)
    return __privateKey, publicKey


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        return False


def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')


def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key, ) == 'SHA-1'
    except:
        return False
