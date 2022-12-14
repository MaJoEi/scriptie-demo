import json
import os
import pickle
import sys
import threading
import time
import uuid

from utils import rsa_crypto, ssi_util, json_util
from utils.client import Client
from pathlib import Path
from Cryptodome.PublicKey import RSA
from utils.json_util import PythonObjectEncoder


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
        self.__current_nonce = 0
        self.__previous_nonces = set()
        self.__abort = False

    # Utility method to sign a message and create an encrypted package containing the message and its signature
    def __prepare_encrypted_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        packet = rsa_crypto.encrypt_blob(packet, self.server_pub_key.read_bytes())
        return packet

    # Utility method to sign a message and create an unencrypted package containing the message and its signature
    def __prepare_packet(self, msg):
        sign = rsa_crypto.sign(msg, self.__private_key.read_bytes())
        packet = pickle.dumps((msg, sign))
        return packet

    # Utility method to verify the validity of a message signature
    def __verify_packet(self, msg, sign):
        if not rsa_crypto.verify(msg, sign, self.server_pub_key.read_bytes()):
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
        self.log_event(f"{err}\n(Verifier: {self.server_did})\n\n")
        self.__abort = True
        msg = self.__create_error_message(err)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

    def __check_error(self, msg):
        if msg["response_type"] == "error":
            sys.stderr.write("The verifier aborted the interaction for the following reason:\n")
            sys.stderr.write(msg["error_message"])
            sys.stderr.write("\n")
            self.__abort = True
            return True
        return False

    """ Mocked session establishment where wallet and verifier share identifiers and cryptographic keys 
    This does not resemble a 'real' session establishment process like the DIDComm or OIDC variants """

    def __mock_session_establishment(self, port):
        self.establish_connection(port)
        packet = self.receive()
        print("Received message 0.1")
        msg, sign = pickle.loads(packet)
        self.server_pub_key = pickle.loads(msg)
        if not self.__verify_packet(msg, sign):
            sys.stderr.write("Message is invalid due to an invalid signature")
            return
        print("Preparing message 0.2")
        msg = pickle.dumps((self.public_key, self.public_did))
        packet = self.__prepare_encrypted_packet(msg)
        self.send(packet)
        packet = self.receive()
        print("Received message 0.3")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            sys.stderr.write("Message is invalid due to an invalid signature")
            return
        self.server_did = pickle.loads(msg)
        print("Session established successfully")

    # "Super"-method to model the proposed extended presentation exchange with contextual access permissions
    def __presentation_exchange(self):
        permitted_attributes = self.__determine_access_permissions()
        if self.__abort:
            return
        self.__data_request(permitted_attributes)

    """ Method to model the first part of the presentation exchange, where the verifier presents their authorization 
        certificate for the context of the transaction to the wallet which in turn computes which attributes the 
        verifier may request. """

    def __determine_access_permissions(self):
        # Message 1
        print("Preparing message 1")
        msg = self.__prepare_request_for_authorization()
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

        # Message 2
        packet = self.receive()
        print("Received message 2")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            err = "Message is invalid due to an invalid signature"
            self.__error_state(err)
            return None
        msg = json.loads(pickle.loads(msg))
        if self.__check_error(msg):
            return None
        context_id = self.__process_auth_cert(msg)
        if self.__abort:
            return None

        # Obtaining of the decision model is mocked here
        dec_model_file = open(f'{self.directory}/decision_models/{context_id}.json')
        dec_model = json.loads(dec_model_file.read())
        dec_model_file.close()
        if not dec_model["contextID"] == context_id:
            err = "ContextID of decision model does not match contextID provided in authorization certificate. " \
                  "Certificate or decision model has possibly been manipulated."
            self.__error_state(err)
            return None

        # Evaluation of the decision model
        permitted_attributes = self.__evaluate_decision_model(dec_model)

        # Returning the result to the verifier
        print("Preparing message 3")
        self.__current_nonce = self.generate_nonce()
        msg_body = {
            "response_type": "mock",
            "client_id": "https://client.example.org/",
            "redirect_uri": "https://client.example.org/",
            "permitted_attributes": permitted_attributes,
            "nonce": self.__current_nonce
        }
        msg = json.dumps(msg_body, cls=PythonObjectEncoder)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)
        return permitted_attributes

    """" Generates a message to request the disclosure of a contextual authorization certificate.
     This message is modeled after the authentication request message of the OpenID for Verifiable Presentations 
     standard (https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request) """

    def __prepare_request_for_authorization(self):
        self.__current_nonce = self.generate_nonce()
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
                                    "RsaSignature2018"
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
            "nonce": self.__current_nonce
        }
        return json.dumps(msg_body)

    """" Mocks the processing of the authorization certificates. This methods checks the nonce re-usage and 
        verifies that the verifier is indeed the subject of the certificate as well as whether the contextID matches
        the url of the decision model.It also asks the user to verify whether the description claim is accurate. 
        It does not verify the signature or check any other fields, which would be necessary in a "real" application """

    def __process_auth_cert(self, msg):
        if not self.__verify_challenge(msg["nonce"]):
            err = "NonceError: Challenge was not returned correctly"
            self.__error_state(err)
            return None
        cert_subject = msg['vp_token']['credentialSubject']['id']
        if not cert_subject == self.server_did:
            err = "Deception detected: Service provided authorization certificate that was not issued to them"
            self.__error_state(err)
            return None
        context_id = msg['vp_token']['credentialSubject']['context']['contextID']
        dec_model_uri = msg['vp_token']['credentialSubject']['context']['decisionModel']
        if not context_id == dec_model_uri[(len(dec_model_uri) - len(str(context_id))):]:
            err = "ContextID does not match decision model. Certificate has possibly been manipulated"
            self.__error_state(err)
            return None
        description = msg['vp_token']['credentialSubject']['context']['description']
        print(f"The services claims that the purpose of this transaction is the following:\n\n{description}\n\nIs this "
              f"accurate? [Y/n]")
        ans = str(input())
        if not (ans == "Y" or ans == "y"):
            err = "ContextError: Service provided incorrect authorization certificate"
            self.__error_state(err)
            return None
        print("Authorization certificate processed successfully")
        return context_id

    """" Method to evaluate a decision model and compute the permitted set of attributes """

    def __evaluate_decision_model(self, dec_model):
        permitted_attributes = set()
        amount_rules = int(dec_model["amount_rules"])
        if amount_rules == 1:
            rule = dec_model["r_1"]
            permitted_attributes.update(self.__process_rule(rule))
            return permitted_attributes
        operators = dec_model["operators"]
        prev_operator = ""
        selection = []
        for x in range(amount_rules):
            rule = dec_model[f"r_{x + 1}"]
            attributes = self.__process_rule(rule)
            if x in range(len(operators)):
                if operators[x] == prev_operator:
                    if operators[x] == "AND":
                        permitted_attributes.update(attributes)
                    elif len(attributes) > 0:
                        selection.append(frozenset(attributes))
                else:
                    match prev_operator:
                        case "XOR":
                            if len(attributes) > 0:
                                selection.append(frozenset(attributes))
                            print("The service may request one of the following options. Which one is your "
                                  "preference?")
                            y = 0
                            for a in selection:
                                y += 1
                                print(f"{y}: {set(a)}")
                            i = int(input())
                            choice = set(selection[i - 1])
                            selection.clear()
                            if operators[x] == "OR":
                                selection.append(frozenset(choice))
                            else:
                                permitted_attributes.update(choice)
                        case "OR":
                            if len(attributes) > 0:
                                selection.append(frozenset(attributes))
                            print(
                                "The service may optionally request one or more of the following options. Which "
                                "options would you be willing to disclose?")
                            print("0: None")
                            y = 0
                            for a in selection:
                                y += 1
                                print(f"{y}: {set(a)}")
                            options = input()
                            options = options.split()
                            tmp = set()
                            for i in range(len(selection) + 1):
                                if i == 0 and i in options:
                                    break
                                elif i+1 in options:
                                    tmp.update(set(selection[i+1]))
                            selection.clear()
                            if operators[x] == "AND":
                                permitted_attributes.update(tmp)
                            else:
                                selection.append(frozenset(tmp))
                        case "AND":
                            if len(attributes) > 0:
                                selection.append(frozenset(attributes))
                        case "":
                            if operators[x] == "AND":
                                permitted_attributes.update(attributes)
                            elif len(attributes) > 0:
                                selection.append(frozenset(attributes))
                    prev_operator = operators[x]
            else:
                match prev_operator:
                    case "AND":
                        permitted_attributes.update(attributes)
                    case "XOR":
                        if len(attributes) > 0:
                            selection.append(frozenset(attributes))
                        print("The service may request one of the following options. Which one is your "
                              "preference?")
                        y = 0
                        for a in selection:
                            y += 1
                            print(f"{y}: {set(a)}")
                        i = int(input())
                        permitted_attributes.update(set(selection[i - 1]))
                        selection.clear()
                    case "OR":
                        if len(attributes) > 0:
                            selection.append(frozenset(attributes))
                        print("The service may optionally request one or more of the following options. Which options "
                              "would you be willing to disclose?")
                        print("0: None")
                        x = 0
                        for a in selection:
                            x += 1
                            print(f"{x}: {set(a)}")
                        options = input()
                        options = options.split()
                        permitted_attributes = set()
                        for o in options:
                            i = int(o)
                            if i == 0:
                                break
                            elif i - 1 in range(len(selection)):
                                permitted_attributes.update(set(selection[i - 1]))
        return permitted_attributes

    """ Util method to process a rule predicate """
    def __process_rule(self, rule):
        condition = rule["condition"]
        if not self.__process_condition(condition):
            return []
        access = rule["access_permissions"]
        predicate = access["predicate"]
        if not (access["verifier"] == "v") or (access["verifier"] == self.server_did):
            return []
        match predicate:
            case "mayRequest":
                return access["attributes"]
            # case "mayRequestOne":
            #   return self.__mayRequestOne(access["attributes"], rule)
            # case "mayRequestN":
            #   return self.__mayRequestN(access["attributes"], rule)
            case _:
                return []

    """ Util method to evaluate the condition of a specific rule predicate """

    def __process_condition(self, condition):
        result = False
        amount = condition["amount"]
        operators = []
        if amount == 0:
            return True
        elif amount == 1:
            return self.__process_condition_predicate(condition["c_1"]["predicate"], condition["c_1"]["parameters"])
        elif amount > 1:
            results = []
            operators = condition["operators"]
            for i in range(amount):
                cond = condition[f"c_{i + 1}"]
                if i == 0:
                    result = self.__process_condition_predicate(cond["predicate"], cond["parameters"])
                else:
                    match operators[i - 1]:
                        case "AND":
                            result = result and self.__process_condition_predicate(cond["predicate"],
                                                                                   cond["parameters"])
                        case "OR":
                            result = result or self.__process_condition_predicate(cond["predicate"],
                                                                                  cond["parameters"])
                        case "XOR":
                            result = result != self.__process_condition_predicate(cond["predicate"],
                                                                                  cond["parameters"])

        return result

    """Processes a condition predicate and returns the result"""

    def __process_condition_predicate(self, predicate, parameters):
        match predicate:
            case "equals":
                return self.__retrieve_attribute_value(parameters[0]) == parameters[1]
            case "greaterThan":
                return int(self.__retrieve_attribute_value(parameters[0])) > parameters[1]
            case "lessThan":
                return int(self.__retrieve_attribute_value(parameters[0])) < parameters[1]
            case "lessThanOrEquals":
                return int(self.__retrieve_attribute_value(parameters[0])) <= parameters[1]
            case "greaterThanOrEquals":
                return int(self.__retrieve_attribute_value(parameters[0])) >= parameters[1]
            case _:
                return True

    """ Processes rule predicates of the type 'mayRequestOne' and returns the set of attribute that may be requested 
            according to this predicate """
    # def __mayRequestOne(self, attributes, rule):
    #    attr_set = []
    #    for attr in attributes:
    #        if attr.startswith("r_"):
    #            sub_rule = rule[attr]
    #            res = frozenset(self.__process_rule(sub_rule))
    #            if not len(res) == 0:
    #                attr_set.append(res)
    #        else:
    #            attr_set.append(attr)
    #    print("The service may request one of the following options. Which one is your preference?")
    #    x = 0
    #    for a in attr_set:
    #        x += 1
    #        print(f"{x}: {set(a)}")
    #    i = int(input())
    #    if i - 1 in range(len(attr_set)):
    #        return set(attr_set[i - 1])
    #    else:
    #        return

    """ Processes rule predicates of the type 'mayRequestN' and returns the set of attribute that may be requested 
        according to this predicate """
    # def __mayRequestN(self, attributes, rule):
    #    attr_set = set()
    #    for attr in attributes:
    #        if attr.startsWith("r_"):
    #            sub_rule = rule[attr]
    #            res = frozenset(self.__process_rule(sub_rule))
    #            if not len(res) == 0:
    #                attr_set.add(res)
    #        else:
    #            attr_set.add(attr)
    #    print("The service may optionally request one or more of the following options. Which options would you be "
    #          "willing to disclose?")
    #    print("0: None")
    #    x = 0
    #    for a in attr_set:
    #        x += 1
    #        print(f"{x}: {set(a)}")
    #    options = input()
    #    options = options.split()
    #    permitted_attributes = set()
    #    for o in options:
    #        i = int(o)
    #        if i == 0:
    #            return set()
    #        elif i - 1 in range(len(attr_set)):
    #            permitted_attributes.update(set(attr_set[i - 1]))
    #        else:
    #            return []
    #    return permitted_attributes

    """ Util method to retrieve the value of a specific attribute from a credential """

    def __retrieve_attribute_value(self, args):
        comps = args.split(".")
        credential_type = comps[0]
        file = open(f'{self.directory}/mock_credentials/{credential_type}.json')
        credential = json.loads(file.read())
        file.close()
        attribute = credential["credentialSubject"]
        for i in range(len(comps) - 1):
            attribute = attribute[comps[i + 1]]
        return attribute

    """ Method to model the second part of the presentation exchange, i.e. the "classic" presentation exchange """

    def __data_request(self, permitted_attributes):
        # Data request
        packet = self.receive()
        print("Received data request")
        packet = rsa_crypto.decrypt_blob(packet, self.__private_key.read_bytes())
        msg, sign = pickle.loads(packet)
        if not self.__verify_packet(msg, sign):
            err = "Message is invalid due to an invalid signature"
            self.__error_state(err)
            return
        msg = json.loads(pickle.loads(msg))
        if self.__check_error(msg):
            return
        nonce = msg["nonce"]
        if not self.__verify_challenge(msg["nonce_challenge"]) or not self.__check_nonce_reuse(nonce):
            err = "Nonce error: either nonce has been reused or challenge was not returned correctly"
            self.__error_state(err)
            return
        valid_request, requested_attributes = self.__verify_access_policy(permitted_attributes, msg)
        if not valid_request:
            err = "Access policy violation: unauthorized attributes requested"
            self.__error_state(err)
            return

        # Ask user if they wish to disclose the requested attributes
        print("The service wants to request the following attributes:")
        print(requested_attributes)
        print("Are you willing to disclose these attributes to them? [Y/n]")
        ans = str(input())
        if not (ans == "Y" or ans == "y"):
            self.__error_state("User is not willing to disclose the requested attributes")
            return

        # Data disclosure
        print("Preparing disclosure of data")
        msg = self.__craft_response_to_data_request(requested_attributes, nonce)
        packet = self.__prepare_encrypted_packet(pickle.dumps(msg))
        self.send(packet)

    def __verify_access_policy(self, permitted_attributes, msg):
        data_request = msg['presentation_definition']['input_descriptors']
        requested_attributes = set()
        for request in data_request:
            credential = request['constraints']['fields']
            credential_type = credential[0]['filter']['pattern']
            for c in credential:
                if not c == credential[0]:
                    attribute_path = c['path'][0]
                    attribute_path = attribute_path.split(".")
                    attribute = ""
                    for i in range(2, len(attribute_path)):
                        attribute = attribute + "." + attribute_path[i]
                    attribute = f"{credential_type}.{attribute[1:]}"
                    if attribute not in permitted_attributes:
                        return False, set()
                    else:
                        requested_attributes.add(attribute)
        return True, requested_attributes

    def __craft_response_to_data_request(self, requested_attributes, nonce):
        # Create a verifiable presentation
        vcs = []
        credential_type, grouped_attributes = ssi_util.group_attributes_by_credential(requested_attributes)
        for credential in credential_type:
            file = open(f'{self.directory}/mock_credentials/{credential}.json')
            vc = json.loads(file.read())
            file.close()
            credential_subject = {}
            attributes_to_delete = []
            do_not_delete = []
            nested_attrs = []
            for a in grouped_attributes[credential]:
                if "." in a:
                    nested_attrs.append(a[:a.find(".")])
            for a in nested_attrs:
                for attr in vc["credentialSubject"][a]:
                    if f"{a}.{attr}" not in grouped_attributes[credential]:
                        del vc["credentialSubject"][a][attr]
            for attribute in vc["credentialSubject"]:
                if (attribute not in grouped_attributes[credential]) and (attribute not in nested_attrs):
                    attributes_to_delete.append(attribute)
            for a in attributes_to_delete:
                del vc['credentialSubject'][a]
            vcs.append(vc)
        vp_token = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": vcs,
            "id": "ebc6f1c2",
            "holder": self.public_did,
            "proof": {
                "type": "RsaSignature2018",
                "created": "2021-03-19T15:30:15Z",
                "challenge": "n-0S6_WzA2Mj",
                "domain": "https://client.example.org/cb",
                "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..GF5Z6TamgNE8QjE3RbiDOj3n_t25_1K7NVWMUASe_OEzQV63GaKdu235MCS3hIYvepcNdQ_ZOKpGNCf0vIAoDA",
                "proofPurpose": "authentication",
                "verificationMethod": "did:example:holder#key-1"
            }
        }

        # Create the descriptor map for the presentation_submission parameter of the response
        descriptor_map = []
        for c in credential_type:
            d = {
                "id": f"{c} with constraints",
                "format": "ldp_vp",
                "path": "$",
                "path_nested": {
                    "format": "ldp_vc",
                    "path": f"$.verifiableCredential[{credential_type.index(c)}]"
                }
            }
            descriptor_map.append(d)

        # Create the body of the authorization response
        msg_body = {
            "client_id": "https://client.example.org/post",
            "redirect_uris": ["https://client.example.org/post"],
            "response_type": "vp_token",
            "response_mode": "post",
            "presentation_submission": {
                "id": "Verifier Authorization Credential example presentation",
                "definition_id": "Verifier Authorization Credential example",
                "descriptor_map": descriptor_map
            },
            "vp_token": vp_token,
            "nonce": nonce
        }
        return json.dumps(msg_body)

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

    def run(self):
        self.__mock_session_establishment(13374)
        self.__presentation_exchange()
        time.sleep(2)
        self.__presentation_exchange()
        time.sleep(2)
        self.__presentation_exchange()

# """ Util method to find out where a statement in parentheses ends """
# def __find_end_statement(self, atoms):
#    expected_p_close = 1
#    for cond in atoms:
#        if cond.startswith("("):
#            expected_p_close += 1
#        elif cond.endswith(")"):
#            expected_p_close -= 1
#            if expected_p_close == 0:
#                return atoms.index(cond)
#    return -1
