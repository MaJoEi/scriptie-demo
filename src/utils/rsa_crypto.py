import os
import rsa
import rsa.randnum
import Crypto
# from Crypto.Cipher import AES
import pickle


def generateKeys():
    dir = os.path.dirname(__file__)
    (publicKey, __privateKey) = rsa.newkeys(1024)
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
    return __privateKey, publicKey


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def encrypt_large_message(message, key):
    aes_key = rsa.randnum.read_random_bits(128)
    nonce, ciphertext, tag = aes_encrypt(message, key)
    encrypted_aes_key = rsa.encrypt(aes_key, key)
    return nonce, ciphertext, tag, encrypted_aes_key


def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic:", plaintext)
        return plaintext
    except ValueError:
        print("Key incorrect or message corrupted")
        return


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
