import os
import pickle
import threading
from utils import rsa_crypto, rsa_crypto2, ssi_util
from utils.client import Client
from pathlib import Path
from Cryptodome.PublicKey import RSA


class Wallet(Client):
    directory = os.path.dirname(__file__)

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.id = 'wallet'
        rsa_crypto2.generate_new_key_pair(self.id)
        self.__private_key = Path(f'{self.directory}/utils/keys/{self.id}private.pem')
        self.public_key = Path(Path(f'{self.directory}/utils/keys/{self.id}public.pem'))
        self.public_did = ssi_util.create_random_did()
        self.server_pub_key = None
        self.server_did = None

    def prepare_encrypted_packet(self, msg):
        sign = rsa_crypto2.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        packet = rsa_crypto2.encrypt_blob(packet, self.server_pub_key.read_bytes())
        return packet

    def prepare_packet(self, msg):
        sign = rsa_crypto2.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        return packet

    def verify_packet(self, msg, sign):
        if not rsa_crypto2.verify(msg, sign, self.server_pub_key.read_bytes()):
            self.interrupt_connection()
            return False
        return True

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
    This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """

    def mock_session_establishment(self, port):
        self.establish_connection(port)
        packet = self.receive()
        print("Received message 1")
        msg, sign = pickle.loads(packet)
        self.server_pub_key = pickle.loads(msg)
        if not self.verify_packet(msg, sign):
            return
        print("Preparing message 2")
        msg = pickle.dumps((self.public_key, self.public_did))
        packet = self.prepare_encrypted_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 3")
        packet = rsa_crypto2.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        self.server_did = pickle.loads(msg)

    def run(self):
        self.mock_session_establishment(13374)
