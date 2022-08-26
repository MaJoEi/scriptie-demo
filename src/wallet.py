import json
import os
import pickle
import threading
import uuid

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
        self.current_nonce = 0

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
        print("Received message 0.1")
        msg, sign = pickle.loads(packet)
        self.server_pub_key = pickle.loads(msg)
        if not self.verify_packet(msg, sign):
            return
        print("Preparing message 0.2")
        msg = pickle.dumps((self.public_key, self.public_did))
        packet = self.prepare_encrypted_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 0.3")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        self.server_did = pickle.loads(msg)
        print("Session established successfully")

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def presentation_exchange(self):
        self.determine_access_permissions()
        self.process_data_request()

    """ Method to model the first part of the presentation exchange, where the verifier presents their authorization 
        certificate for the context of the transaction to the wallet which in turn computes which attributes the 
        verifier may request. """
    def determine_access_permissions(self):
        # Message 1
        print("Preparing message 1")
        msg = self.prepare_request_for_authorization()
        packet = self.prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        #Message 2
        packet = self.receive()
        print("Received message 2")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.verify_packet(msg, sign):
            return
        msg = json.loads(pickle.loads(msg))
        self.process_auth_cert(msg)

        # Obtaining of the decision model is mocked here


    """" Generates a message to request the disclosure of a contextual authorization certificate.
     This message is modeled after the authentication request message of the OpenID for Verifiable Presentations 
     standard (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request) """
    def prepare_request_for_authorization(self):
        self.current_nonce = self.generate_nonce()
        msg_body = {
            "response_type": "vp_token",
            "client_id": "https://client.example.org/",
            "redirect_uri": "https://client.example.org/",
            "presentation_definition": {
                "id": "Request for contextual authorization",
                "input_descriptors": [
                    {
                        "id": "Verifier Authorization Credential",
                        "format": {
                            "ldp_vc": {
                                "proof_type": [
                                    "Ed25519Signature2018"
                                ]
                            }
                        },
                        "constraints": {
                            "fields": [
                                {
                                    "path": [
                                        "$.type"
                                    ],
                                    "filter": {
                                        "type": "string",
                                        "pattern": "VerifierAuthorizationCredential"
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            "nonce": self.current_nonce
        }
        return json.dumps(msg_body)

    """" Mocks the processing of the authorization certificates. This methods checks the nonce re-usage and 
        verifies that the verifier is indeed the subject of the certificate as well as whether the contextID matches
        the url of the decision model.It also asks the user to verify whether the description claim is accurate. 
        It does not verify the signature or check any other fields, which would be necessary in a "real" application """
    def process_auth_cert(self, msg):
        if not self.verify_nonce(msg["nonce"]):
            return
        cert_subject = msg['vp_token']['credentialSubject']['id']
        if not cert_subject == self.server_did:
            return
        ctxt_id = msg['vp_token']['credentialSubject']['context']['contextID']
        dec_model_uri = msg['vp_token']['credentialSubject']['context']['decisionModel']
        if not ctxt_id == dec_model_uri[(len(dec_model_uri)-len(str(ctxt_id))):]:
            return
        description = msg['vp_token']['credentialSubject']['context']['description']
        print(f"The services claims that the purpose of this transaction is the following:\n\n{description}\n\nIs this "
              f"accurate? [Y/n]")
        ans = str(input())
        if not (ans == "Y" or ans == "y"):
            return
        print("Authorization certificate processed successfully")

    """ Method to model the second part of the presentation exchange, i.e. the "actual" presentation exchange """
    def process_data_request(self):
        pass

    def evaluate_decision_model(self):

        pass

    def generate_nonce(self):
        return uuid.uuid4().hex

    def verify_nonce(self, nonce):
        return nonce == self.current_nonce

    def run(self):
        self.mock_session_establishment(13374)
        self.presentation_exchange()
