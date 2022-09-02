import json
import os
import pickle
import threading
from utils import ssi_util, rsa_crypto, json_util
from utils.json_util import PythonObjectEncoder, as_python_object
from utils.server import Server
from pathlib import Path
import uuid
import sys


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
        self.__previous_nonces = set()
        self.__current_nonce = 0
        self.__abort = False

    # Utility method to sign a message and create an encrypted package containing the message and its signature
    def __prepare_encrypted_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        packet = rsa_crypto.encrypt_blob(packet, self.client_pub_key.read_bytes())
        return packet

    # Utility method to sign a message and create an unencrypted package containing the message and its signature
    def __prepare_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        return packet

    # Utility method to verify the validity of a message signature
    def __verify_packet(self, msg, sign):
        if not rsa_crypto.verify(msg, sign, self.client_pub_key.read_bytes()):
            return False
        return True

    # Utility method to create an error message in OIDC format to be sent to the verifier in case of an exception
    def __create_error_message(self, msg):
        self.__current_nonce = self.generate_nonce()
        msg_body = {
            "response_type": "error",
            "client_id": "https://client.example.org/",
            "redirect_uri": "https://client.example.org/",
            "error_message": msg,
            "nonce": self.__current_nonce
        }
        return json.dumps(msg_body)

    def __error_state(self, err):
        sys.stderr.write(f"{err}\n")
        self.__abort = True
        msg = self.__create_error_message(err)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

    def __check_error(self, msg):
        if msg["response_type"] == "error":
            sys.stderr.write("The wallet aborted the interaction for the following reason:\n")
            sys.stderr.write(msg["error_message"])
            sys.stderr.write("\n")
            self.__abort = True
            return True
        return False

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
        This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """
    def __mock_session_establishment(self):
        self.establish_connection()
        print("Preparing message 0.1")
        msg = pickle.dumps(self.public_key)
        packet = self.__prepare_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 0.2")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        self.client_pub_key, self.client_did = pickle.loads(msg)
        if not self.__verify_packet(msg, sign):
            return
        print("Preparing message 0.3")
        msg = pickle.dumps(self.public_did)
        packet = self.__prepare_encrypted_packet(msg)
        self.send(packet)

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def __presentation_exchange(self, context_id, description):
        print("Generating auth certificate")
        authorizer_did = ssi_util.create_random_did()
        auth_cert = json.loads(ssi_util.create_auth_cert(authorizer_did, self.public_did, context_id, description))
        permitted_attributes, challenge = self.__present_auth_certificate(auth_cert)
        if self.__abort:
            return
        self.__data_request(permitted_attributes, challenge)

    """ Method to model the first part of the presentation exchange, where the verifier presents their authorization 
    certificate for the context of the transaction to the wallet which in turn computes which attributes the verifier 
    may request """
    def __present_auth_certificate(self, auth_cert):
        # Message 1
        packet = self.receive()
        print("Received message 1")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            self.__error_state("Message is invalid due to an invalid signature")
            return None, None
        msg = json.loads(pickle.loads(msg))
        if self.__check_error(msg):
            return None, None
        nonce = msg["nonce"]
        self.__process_auth_request(msg, nonce)

        # Message 2
        print("Preparing message 2")
        msg = self.__prepare_presentation_auth_cert(nonce, auth_cert)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        # Message 3
        packet = self.receive()
        print("Received message 3")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            self.__error_state("Message is invalid due to an invalid signature")
            return None, None
        msg = json.loads(pickle.loads(msg), object_hook=as_python_object)
        if self.__check_error(msg):
            return None, None
        nonce = msg["nonce"]
        if not self.__check_nonce_reuse(nonce):
            self.__error_state("Nonce reuse detected")
            return None, None
        permitted_attributes = msg["permitted_attributes"]
        return permitted_attributes, nonce

    """" Generates a message to disclose a contextual authorization certificate.
         This message is modeled after the authentication response message of the OpenID for Verifiable Presentations 
         standard (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response) """
    def __prepare_presentation_auth_cert(self, nonce, auth_cert):
        msg_body = {
            "client_id": "https://client.example.org/post",
            "redirect_uris": ["https://client.example.org/post"],
            "response_type": "vp_token",
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
    def __process_auth_request(self, msg, nonce):
        if not self.__check_nonce_reuse(nonce):
            self.__error_state("Nonce reuse detected")
            return False
        requested_type = msg["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]["filter"][
            "pattern"]
        if not requested_type == "VerifierAuthorizationCredential":
            self.__error_state(f"Unexpected credential type requested. Expected VerifierAuthorizationCredential, got "
                               f"{requested_type} instead")
            return False

    """ Method to model the second part of the presentation exchange, i.e. the "actual" presentation exchange """
    def __data_request(self, permitted_attributes, challenge):
        # Data request
        print("Preparing data request")
        msg = self.__prepare_data_request(permitted_attributes, challenge)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        # Response to data request
        packet = self.receive()
        print("Received response to data request")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            sys.stderr.write("Message is invalid due to an invalid signature")
            return
        msg = json.loads(pickle.loads(msg))
        if self.__check_error(msg):
            return
        nonce = msg["nonce"]
        if not self.__check_nonce_reuse(nonce):
            sys.stderr.write("Nonce reuse detected")
            return
        attribute_values = self.__obtain_attribute_values(msg)
        print("The verifier received the following data for the requested attributes:")
        print(attribute_values)

    """ Prepares the data request in the form of a (mocked) OpenID Authorization Request """
    def __prepare_data_request(self, permitted_attributes, challenge):
        credential_types, attribute_dict = ssi_util.group_attributes_by_credential(sorted(permitted_attributes))
        input_descriptors = []
        self.__current_nonce = self.generate_nonce()
        for c in credential_types:
            descriptor = {
                "id": f"{c} with constraints",
                "format": {
                    "ldp_vc": {
                        "proof_type": [
                            "RsaSignature2018"
                        ]
                    }
                }
            }
            fields = [{
                "path": [
                    "$.type"
                ],
                "filter": {
                    "type": "string",
                    "pattern": c
                }
            }]
            for a in attribute_dict[c]:
                fields.append({
                    "path": [
                        f"$.credentialSubject.{a}"
                    ]
                })
            constraints = {
                "constraints": {
                    "limit_disclosure": "required",
                    "fields": fields
                }
            }
            descriptor.update(constraints)
            input_descriptors.append(descriptor)
        msg_body = {
            "response_type": "vp_token",
            "client_id": "https://client.example.org/",
            "redirect_uri": "https://client.example.org/",
            "presentation_definition": {
                "id": "Request for contextual authorization",
                "input_descriptors": input_descriptors
            },
            "nonce_challenge": challenge,
            "nonce": self.__current_nonce
        }
        return json.dumps(msg_body)

    def __obtain_attribute_values(self, msg):
        attr_value_dict = {}
        vcs = msg['vp_token']['verifiableCredential']
        for vc in vcs:
            credential_type = vc['type'][1]
            for a in vc['credentialSubject']:
                attr = f"{credential_type}.{a}"
                attr_value_dict.update({attr: vc['credentialSubject'][a]})
        return attr_value_dict

    def generate_nonce(self):
        return uuid.uuid4().hex

    def __verify_challenge(self, nonce):
        return nonce == self.__current_nonce

    """" Method to verify that a nonce has not been re-used """
    def __check_nonce_reuse(self, nonce):
        if nonce in self.__previous_nonces:
            return False
        else:
            self.__previous_nonces.add(nonce)
            return True

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def __malicious_presentation_exchange(self, context_id, description):
        print("Generating auth certificate")
        authorizer_did = ssi_util.create_random_did()
        auth_cert = json.loads(ssi_util.create_auth_cert(authorizer_did, self.public_did, context_id, description))
        permitted_attributes, challenge = self.__present_auth_certificate(auth_cert)
        if self.__abort:
            return
        self.__malicicous_data_request(permitted_attributes, challenge)

    def __malicicous_data_request(self, permitted_attributes, challenge):
        # Data request
        print("Preparing data request")
        forbidden_attributes = {'CreditCardCredential.cardNumber', 'CreditCardCredential.expirationDate',
                                'CreditCardCredential.secretNumber'}
        permitted_attributes.update(forbidden_attributes)
        msg = self.__prepare_data_request(permitted_attributes, challenge)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        # Response to data request
        packet = self.receive()
        print("Received response to data request")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            sys.stderr.write("Message is invalid due to an invalid signature")
            return
        msg = json.loads(pickle.loads(msg))
        if self.__check_error(msg):
            return
        nonce = msg["nonce"]
        if not self.__check_nonce_reuse(nonce):
            sys.stderr.write("Nonce reuse detected")
            return
        attribute_values = self.__obtain_attribute_values(msg)
        print("The verifier received the following data for the requested attributes:")
        print(attribute_values)

    def run(self):
        self.__mock_session_establishment()
        f = open(f'{self.directory}/decision_models/contextIDs.json').read()
        context_id = json.loads(f)["notaris"]["id"]
        description = json.loads(f)["notaris"]["description"]
        self.__presentation_exchange(context_id, description)
        context_id = json.loads(f)["app_form"]["id"]
        description = json.loads(f)["app_form"]["description"]
        self.__presentation_exchange(context_id, description)
        context_id = json.loads(f)["notaris"]["id"]
        description = json.loads(f)["notaris"]["description"]
        self.__malicious_presentation_exchange(context_id, description)
