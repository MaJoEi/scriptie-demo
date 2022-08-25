import json
import jsondiff
import requests
import rsa
import os

"""This file contains basic SSI utility functions, such as the creation and resolving of DIDs.
For functions involving DIDs and VCs (whenever not mocked), we utilize REST APIs from walt.id's SSI Kit (primarily the 
Custodian API)"""


# Creates a keypair with an alias via the walt.id Custodian API
"""def create_and_export_keypair(oid):
    # Creation of the key pair
    keygen_url = "https://custodian.ssikit.walt-test.cloud/keys/generate"
    keygen_body = {"keyAlgorithm": "RSA"}
    keygen_resp = requests.post(keygen_url, json=keygen_body)
    resp = json.loads(keygen_resp.text)
    key_id = resp['keyId']['id']

    # Obtaining the public key
    keyexport_url = "https://custodian.ssikit.walt-test.cloud/keys/export"
    body = {
        "keyAlias": key_id,
        "format": "PEM",
        "exportPrivate": False
    }
    resp = requests.post(keyexport_url, json=body).text
    pem_prefix = '-----BEGIN RSA PRIVATE KEY-----\n'
    pem_suffix = '\n-----END RSA PRIVATE KEY-----\n'
    key = '{}{}{}'.format(pem_prefix, resp[28:], pem_suffix)
    # publicKey = RSA.importKey(resp)

    # Obtaining the private key
    body = {
        "keyAlias": key_id,
        "format": "PEM",
        "exportPrivate": True
    }
    resp = requests.post(keyexport_url, json=body).text
    # print(resp[28:897])
    # resp = resp[:11] + "RSA " + resp[11:907] + "RSA " + resp[907:]
    # dir = os.path.dirname(__file__)
    # filename = os.path.join(dir, 'keys', 'privateKey.pem')
    # with open(filename, 'wb') as p:
    #     p.write(bytes(resp.encode()))
    # with open(filename, 'rb') as p:
    #     __privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    #     print(__privateKey)
    pem_prefix = '-----BEGIN RSA PRIVATE KEY-----\n'
    pem_suffix = '\n-----END RSA PRIVATE KEY-----\n'
    key = '{}{}{}'.format(pem_prefix, resp[28:897], pem_suffix)
    __privateKey = RSA.importKey(key)

    return key_id, __privateKey, publicKey"""


# Creates a DID via the Custodian API of the walt.id SSI Kit
def create_did(key_id):
    didcreate_url = "https://custodian.ssikit.walt-test.cloud/did/create"
    didcreate_body = {
        "method": "key",
        "keyAlias": str(key_id)
    }
    didresp = requests.post(didcreate_url, json=didcreate_body)
    return didresp.text


# Creates a random key from which a did can be created
def create_random_key():
    keygen_url = "https://custodian.ssikit.walt-test.cloud/keys/generate"
    keygen_body = {"keyAlgorithm": "RSA"}
    keygen_resp = requests.post(keygen_url, json=keygen_body)
    resp = json.loads(keygen_resp.text)
    return resp['keyId']['id']


# Creates random "mocked" DID
def create_random_did():
    # Create a key on which the DID will be built, such that this function does not generate the same DID every time
    keyalias = create_random_key()

    # Creation of the DID
    didcreate_url = "https://custodian.ssikit.walt-test.cloud/did/create"
    didcreate_body = {
        "method": "key",
        "keyAlias": str(keyalias)
    }
    didresp = requests.post(didcreate_url, json=didcreate_body)
    return didresp.text


# Resolves a DID to its corresponding DID document
def resolve_did(did):
    didresolve_url = "https://custodian.ssikit.walt-test.cloud/did/resolve"
    didresolve_body = {"did": did}
    resp = requests.post(didresolve_url, json=didresolve_body)
    return resp.text


# Creates a mock authorization certificate in the form of a verifiable credential
def create_auth_cert(issuer_did, subject_did, context_id, description):
    schema = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.overidentification-protection-authority.gov/2022/authorizations/v1"
        ],

        "id": "http://overidentification-protection-authority.gov/certificates/1337",

        "type": ["VerifiableCredential", "AuthorizationCredential"],

        "issuer": issuer_did,

        "issuanceDate": "2022-07-06T14:23:24Z",

        "credentialSubject": {

            "id": subject_did,

            "context": {
                "contextID": context_id,
                "decisionModel": f"https://overidentification-protection-authority.gov/context-models/{context_id}",
                "description": description
            }
        },

        "proof": {

            "type": "RsaSignature2018",

            "created": "2017-06-18T21:19:10Z",

            "proofPurpose": "assertionMethod",

            "verificationMethod": "https://example.edu/issuers/565049#key-1",

            "jws": "eyJhbGciOiJSUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..TCYt5XsITJX1CxPCT8yAV - TVkIEq_PbChOMqsLfRoPsnsgw5WEuts01mq - pQy7UJiN5mgRxD - WUcX16dUEMGlv50aqzpqh4Qktb3rk - BuQy72IFLOqV0G_zS245 - kronKb78cPN25DGlcTwLtjPAYuNzVBAh4vGHSrQyHUdBBPM"
        }
    }
    auth_cert = json.dumps(schema)
    print(auth_cert)
    return auth_cert
