import os
import pickle
import threading
from utils import ssi_util, rsa_crypto
from utils.server import Server
from pathlib import Path


class Verifier(Server):
    directory = os.path.dirname(__file__)

    def __init__(self, port, threadID):
        threading.Thread.__init__(self)
        self.port = port
        self.threadID = threadID
        self.s.bind((self.host, port))
        self.id = f'verifier{port}'
        rsa_crypto.generate_new_key_pair(self.id)
        self.__private_key = Path(f'{self.directory}/utils/keys/{self.id}private.pem')
        self.public_key = Path(Path(f'{self.directory}/utils/keys/{self.id}public.pem'))
        self.public_did = ssi_util.create_random_did()
        self.client_pub_key = None
        self.client_did = None

    # Utility method to sign a message and create an encrypted package containing the message and its signature
    def prepare_encrypted_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        packet = rsa_crypto.encrypt_blob(packet, self.client_pub_key.read_bytes())
        return packet

    # Utility method to sign a message and create an unencrypted package containing the message and its signature
    def prepare_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        return packet

    # Utility method to verify the validity of a message signature
    def verify_packet(self, msg, sign):
        if not rsa_crypto.verify(msg, sign, self.client_pub_key.read_bytes()):
            self.send('interrupt')
            self.interrupt_connection()
            return False
        return True

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
        This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """
    def mock_session_establishment(self):
        self.establish_connection()
        print("Preparing first message")
        msg = pickle.dumps(self.public_key)
        packet = self.prepare_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 2")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        self.client_pub_key, self.client_did = pickle.loads(msg)
        if not self.verify_packet(msg, sign):
            return
        print("Preparing message 3")
        msg = pickle.dumps(self.public_did)
        packet = self.prepare_encrypted_packet(msg)
        self.send(packet)

    def run(self):
        self.mock_session_establishment()
