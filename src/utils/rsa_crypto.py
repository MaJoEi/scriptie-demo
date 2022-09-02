""" Sources: https://gist.github.com/dustindorroh/7488f8016bc360fb1182d037dcee2a27 for most of the code
https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples for the signature functions """

import os
import zlib
import base64
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from pathlib import Path
from hashlib import sha512
from Cryptodome.Signature.pkcs1_15 import PKCS115_SigScheme
from Cryptodome.Hash import SHA256


def generate_new_key_pair(oid):
    directory = os.path.dirname(__file__)

    # Generate a public/ private key pair using 4096 bits key length (512 bytes)
    new_key = RSA.generate(4096, e=65537)

    # The private key in PEM format
    __private_key = new_key.exportKey("PEM")

    # The public key in PEM Format
    public_key = new_key.publickey().exportKey("PEM")

    # filename = os.path.join(directory, 'keys', f'{oid}private.pem')
    private_key_path = Path(f'{directory}/keys/{oid}private.pem')
    private_key_path.touch(mode=0o600)
    private_key_path.write_bytes(__private_key)

    # filename = os.path.join(directory, 'keys', f'{oid}public.pem')
    public_key_path = Path(f'{directory}/keys/{oid}public.pem')
    public_key_path.touch(mode=0o664)
    public_key_path.write_bytes(public_key)


# Our Encryption Function
def encrypt_blob(blob, public_key):
    # Import the Public Key and use for encryption using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    # compress the data first
    blob = zlib.compress(blob)
    # In determining the chunk size, determine the private key length used in bytes
    # and subtract 42 bytes (when using PKCS1_OAEP). The data will be in encrypted
    # in chunks
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted = bytearray()

    while not end_loop:
        # The chunk
        chunk = blob[offset:offset + chunk_size]

        # If the data chunk is less then the chunk size, then we need to add
        # padding with " ". This indicates the we reached the end of the file
        # so we end loop here
        if len(chunk) % chunk_size != 0:
            end_loop = True
            # chunk += b" " * (chunk_size - len(chunk))
            chunk += bytes(chunk_size - len(chunk))
        # Append the encrypted chunk to the overall encrypted file
        encrypted += rsa_key.encrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    # Base 64 encode the encrypted file
    return base64.b64encode(encrypted)


# Our Decryption Function
def decrypt_blob(encrypted_blob, private_key):
    # Import the Private Key and use for decryption using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    # Base 64 decode the data
    encrypted_blob = base64.b64decode(encrypted_blob)

    # In determining the chunk size, determine the private key length used in bytes.
    # The data will be in decrypted in chunks
    chunk_size = 512
    offset = 0
    decrypted = bytearray()

    # keep loop going as long as we have chunks to decrypt
    while offset < len(encrypted_blob):
        # The chunk
        chunk = encrypted_blob[offset: offset + chunk_size]

        # Append the decrypted chunk to the overall decrypted file
        decrypted += rsakey.decrypt(chunk)

        # Increase the offset by chunk size
        offset += chunk_size

    # return the decompressed decrypted data
    return zlib.decompress(decrypted)


def sign(msg, key):
    priv_key = RSA.importKey(key)
    msg_hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(priv_key)
    signature = signer.sign(msg_hash)
    return signature


def verify(msg, signature, key):
    pub_key = RSA.importKey(key)
    msg_hash = SHA256.new(msg)
    verifier = PKCS115_SigScheme(pub_key)
    try:
        verifier.verify(msg_hash, signature)
        print("Signature is valid.")
        return True
    except:
        print("Signature is invalid.")
        return False


# def sign(msg, key):
#    priv_key = RSA.importKey(key)
#    print(priv_key)
#    msg_hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
#    signature = pow(msg_hash, priv_key.d, priv_key.n)
#    return signature


# def verify(msg, signature, key):
#    pub_key = RSA.importKey(key)
#    msg_hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
#    hashFromSignature = pow(signature, pub_key.e, pub_key.n)
#    print("Signature valid:", msg_hash == hashFromSignature)


# generate_new_key_pair() # run if you don't already have a key pair
#
# private_key = Path('private.pem')
# public_key = Path('public.pem')
# unencrypted_file = Path('deadbeef.txt')
# encrypted_file = unencrypted_file.with_suffix('.dat')
#
# encrypted_msg = encrypt_blob(unencrypted_file.read_bytes(), public_key)
# decrypt_blob(encrypted_msg, private_key)
