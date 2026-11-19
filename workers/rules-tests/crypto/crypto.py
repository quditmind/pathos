# Test fixture for workers/rules/pathos-crypto.yml (Python). Not executed.
import hashlib
import hmac
import os
import random
import secrets
import ssl

import httpx
import jwt
from Crypto.Cipher import AES, DES, ARC4
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def hashing(data):
    # ruleid: pathos.crypto.python.weak-hash
    a = hashlib.md5(data).hexdigest()
    # ruleid: pathos.crypto.python.weak-hash
    b = hashlib.new("sha1", data)
    # ruleid: pathos.crypto.python.weak-hash
    c = hashes.SHA1()
    # ok: pathos.crypto.python.weak-hash
    d = hashlib.md5(data, usedforsecurity=False).hexdigest()
    # ok: pathos.crypto.python.weak-hash
    e = hashlib.sha256(data).hexdigest()
    return a, b, c, d, e


def ciphers(key, data):
    # ruleid: pathos.crypto.python.weak-cipher
    des = DES.new(key, DES.MODE_CBC, iv=os.urandom(8))
    # ruleid: pathos.crypto.python.weak-cipher
    rc4 = ARC4.new(key)
    # ruleid: pathos.crypto.python.weak-cipher
    tdes = Cipher(algorithms.TripleDES(key), modes.CBC(os.urandom(8)))
    # ok: pathos.crypto.python.weak-cipher
    aes = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)))
    # ruleid: pathos.crypto.python.ecb-mode
    ecb = AES.new(key, AES.MODE_ECB)
    # ruleid: pathos.crypto.python.ecb-mode
    ecb2 = Cipher(algorithms.AES(key), modes.ECB())
    # ok: pathos.crypto.python.ecb-mode
    gcm = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
    # ruleid: pathos.crypto.python.static-iv
    cbc = AES.new(key, AES.MODE_CBC, b"0000000000000000")
    # ruleid: pathos.crypto.python.static-iv
    ctr = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16))
    # ruleid: pathos.crypto.python.static-iv
    gcm2 = AES.new(key, AES.MODE_GCM, nonce=b"fixednonce12")
    # ok: pathos.crypto.python.static-iv
    cbc2 = AES.new(key, AES.MODE_CBC, os.urandom(16))
    return des, rc4, tdes, aes, ecb, ecb2, gcm, cbc, ctr, gcm2, cbc2


def keys():
    # ruleid: pathos.crypto.python.small-rsa-key
    k1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    # ruleid: pathos.crypto.python.small-rsa-key
    k2 = RSA.generate(512)
    # ok: pathos.crypto.python.small-rsa-key
    k3 = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return k1, k2, k3


def tokens(user):
    # ruleid: pathos.crypto.python.insecure-random-secret
    reset_token = "".join(random.choice("abcdef0123456789") for _ in range(32))
    # ruleid: pathos.crypto.python.insecure-random-secret
    user.session_id = random.getrandbits(128)
    # ok: pathos.crypto.python.insecure-random-secret
    api_key = secrets.token_urlsafe(32)
    # ok: pathos.crypto.python.insecure-random-secret
    delay = random.uniform(0.5, 1.5)
    return reset_token, api_key, delay


def tls(url):
    # ruleid: pathos.crypto.python.tls-verification-disabled
    ctx = ssl._create_unverified_context()
    good = ssl.create_default_context()
    # ruleid: pathos.crypto.python.tls-verification-disabled
    good.check_hostname = False
    # ruleid: pathos.crypto.python.tls-verification-disabled
    good.verify_mode = ssl.CERT_NONE
    # ruleid: pathos.crypto.python.tls-verification-disabled
    r = httpx.get(url, verify=False)
    # ok: pathos.crypto.python.tls-verification-disabled
    r2 = httpx.get(url, verify="/etc/ssl/private-ca.pem")
    return ctx, r, r2


def hardcoded(data, payload):
    # ruleid: pathos.crypto.python.hardcoded-key
    c = AES.new(b"0123456789abcdef", AES.MODE_GCM)
    # ruleid: pathos.crypto.python.hardcoded-key
    f = Fernet(b"not-a-real-fernet-key-only-a-test-fixture=")
    # ruleid: pathos.crypto.python.hardcoded-key
    mac = hmac.new(b"fixture-mac-key", data, "sha256")
    # ruleid: pathos.crypto.python.hardcoded-key
    token = jwt.encode(payload, "fixture-signing-key", algorithm="HS256")
    # ok: pathos.crypto.python.hardcoded-key
    token2 = jwt.encode(payload, os.environ["JWT_KEY"], algorithm="HS256")
    # ok: pathos.crypto.python.hardcoded-key
    c2 = AES.new(os.environ["AES_KEY"].encode(), AES.MODE_GCM)
    return c, f, mac, token, token2, c2
