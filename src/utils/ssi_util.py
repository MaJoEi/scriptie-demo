import json

import requests


# Creates a DID via the Custodian API of the walt.id SSI Kit
def create_did():
    # Create a key on which the DID will be built
    keygen_url = "https://custodian.ssikit.walt-test.cloud/keys/generate"
    keygen_body = {"keyAlgorithm": "RSA"}
    keygen_resp = requests.post(keygen_url, json=keygen_body)
    resp = json.loads(keygen_resp.text)
    keyalias = resp['keyId']['id']

    # Creation of the DID
    didcreate_url = "https://custodian.ssikit.walt-test.cloud/did/create"
    didcreate_body = {
        "method": "key",
        "keyAlias": str(keyalias)
    }
    didresp = requests.post(didcreate_url, json=didcreate_body)
    return didresp.text
