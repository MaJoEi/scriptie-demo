import json
import os
import pickle
import threading
from utils import ssi_util, rsa_crypto, json_util
from utils.json_util import PythonObjectEncoder, as_python_object
from utils.server import Server
from pathlib import Path
import uuid


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
        self.public_key = Path(f'{self.directory}/utils/keys/{self.id}public.pem')
        self.public_did = ssi_util.create_random_did()
        self.client_pub_key = None
        self.client_did = None
        self.previous_nonces = set()

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
        print("Preparing message 0.1")
        msg = pickle.dumps(self.public_key)
        packet = self.prepare_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 0.2")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        self.client_pub_key, self.client_did = pickle.loads(msg)
        if not self.verify_packet(msg, sign):
            return
        print("Preparing message 0.3")
        msg = pickle.dumps(self.public_did)
        packet = self.prepare_encrypted_packet(msg)
        self.send(packet)

    """" Method to verify that a nonce has not been re-used """
    def nonce_verification(self, nonce):
        if nonce in self.previous_nonces:
            return False
        else:
            self.previous_nonces.add(nonce)
            return True

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def presentation_exchange(self, context_id, description):
        print("Generating auth certificate")
        authorizer_did = ssi_util.create_random_did()
        auth_cert = json.loads(ssi_util.create_auth_cert(authorizer_did, self.public_did, context_id, description))
        permitted_attributes = self.present_auth_certificate(auth_cert)
        self.data_request(permitted_attributes)

    """ Method to model the first part of the presentation exchange, where the verifier presents their authorization 
    certificate for the context of the transaction to the wallet which in turn computes which attributes the verifier 
    may request """
    def present_auth_certificate(self, auth_cert):
        # Message 1
        packet = self.receive()
        print("Received message 1")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        msg = json.loads(pickle.loads(msg))
        nonce = msg["nonce"]
        self.process_auth_request(msg, nonce)

        # Message 2
        print("Preparing message 2")
        msg = self.prepare_presentation_auth_cert(nonce, auth_cert)
        packet = self.prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        # Message 3
        packet = self.receive()
        print("Received message 3")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        msg = json.loads(pickle.loads(msg), object_hook=as_python_object)
        nonce = msg["nonce"]
        if not self.nonce_verification(nonce):
            return
        permitted_attributes = msg["permitted_attributes"]
        return permitted_attributes
        print(permitted_attributes)

    """" Generates a message to disclose a contextual authorization certificate.
         This message is modeled after the authentication response message of the OpenID for Verifiable Presentations 
         standard (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response) """
    def prepare_presentation_auth_cert(self, nonce, auth_cert):
        msg_body = {
            "client_id": "https://client.example.org/post",
            "redirect_uris": ["https://client.example.org/post"],
            "response_types": "vp_token",
            "response_mode": "post",
            "presentation_submission": {
                "id": "Verifier Authorization Credential example presentation",
                "definition_id": "Verifier Authorization Credential example",
                "descriptor_map": [
                    {
                        "id": "Verifier Authorization Credential",
                        "format": "ldp_vc",
                        "path": "$"
                    }
                ]
            },
            "vp_token": auth_cert,
            "nonce": nonce
        }
        return json.dumps(msg_body)

    """" Mocks the processing of the request for contextual authorization by only checking for nonce re-usage and 
    verifying that it is indeed asking for a VerifierAuthorizationCredential. Other fields are ignored. In a real 
    application, all fields would need to be processed """
    def process_auth_request(self, msg, nonce):
        if not self.nonce_verification(nonce):
            self.interrupt_connection()
            return False
        requested_type = msg["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]["filter"][
            "pattern"]
        if not requested_type == "VerifierAuthorizationCredential":
            self.interrupt_connection()
            return False

    """ Method to model the second part of the presentation exchange, i.e. the "actual" presentation exchange """
    def data_request(self, permitted_attributes):
        pass

    def generate_nonce(self):
        return uuid.uuid4().hex

    def run(self):
        self.mock_session_establishment()
        f = open(f'{self.directory}/decision_models/contextIDs.json').read()
        context_id = json.loads(f)["app_form"]["id"]
        description = json.loads(f)["app_form"]["description"]
        self.presentation_exchange(context_id, description)
