import os
import pickle
import threading
from utils import rsa_crypto, ssi_util
from utils.client import Client
from pathlib import Path
from Cryptodome.PublicKey import RSA


class Wallet(Client):
    directory = os.path.dirname(__file__)

    def __init__(self, threadID):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.id = 'wallet'
        rsa_crypto.generate_new_key_pair(self.id)
        self.__private_key = Path(f'{self.directory}/utils/keys/{self.id}private.pem')
        self.public_key = Path(Path(f'{self.directory}/utils/keys/{self.id}public.pem'))
        self.public_did = ssi_util.create_random_did()
        self.server_pub_key = None
        self.server_did = None

    # Utility method to sign a message and create an encrypted package containing the message and its signature
    def prepare_encrypted_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        packet = rsa_crypto.encrypt_blob(packet, self.server_pub_key.read_bytes())
        return packet

    # Utility method to sign a message and create an unencrypted package containing the message and its signature
    def prepare_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        return packet

    # Utility method to verify the validity of a message signature
    def verify_packet(self, msg, sign):
        if not rsa_crypto.verify(msg, sign, self.server_pub_key.read_bytes()):
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
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        self.server_did = pickle.loads(msg)

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def presentation_exchange(self):
        self.determine_access_permissions()
        self.process_data_request()

    """ Method to model the first part of the presentation exchange, where the verifier presents their authorization 
        certificate for the context of the transaction to the wallet which in turn computes which attributes the verifier 
        may request """
    def determine_access_permissions(self):
        pass

    """ Method to model the second part of the presentation exchange, i.e. the "actual" presentation exchange """
    def process_data_request(self):
        pass

    def run(self):
        self.mock_session_establishment(13374)
