import os

import requests
import json
import threading

import rsa

from utils import ssi_util, server, client, rsa_crypto
from utils.client import Client
from utils.server import Server
from verifier import Verifier
from wallet import Wallet

"""auth_url = "https://wallet.walt.id/api/auth/login"
userinfo_url = "https://wallet.walt.id/api/auth/userInfo"
didcreate_url = "https://custodian.ssikit.walt-test.cloud/did/create"

auth = {
    "id": "string",
    "email": "string",
    "password": "string",
    "token": "string",
    "ethAccount": "string",
    "did": "string"
}

response = requests.post(auth_url, json=auth)
resp = json.loads(response.text)
token = resp['token']

headers = {"Authorization": f"Bearer {token}"}

userinfo_req = requests.get(userinfo_url, headers=headers)
userinfo = json.loads(userinfo_req.text)

print(userinfo)

didcreate_body = {
    "method": "key"
}

didresp = requests.post(didcreate_url, json=didcreate_body)
print(didresp.text)"""

test_wallet = Wallet(1)
test_verifier = Verifier(13374, 2)
test_verifier.start()
test_wallet.start()

# ssi_util.create_and_export_keypair(123)



# test_client = Client(1)
# test_server = Server(13374, 2)
# test_client.start()
# test_server.start()
