import pytest
import json

from ectf25_design.encoder import Encoder
from ectf25_design.gen_secrets import gen_secrets
from ectf25_design.gen_subscription import gen_subscription


def test_secret_generation():
    assert gen_secrets([1, 2, 3, 4]) != None 

def test_subcription_generation():
    secrets = gen_secrets([1, 2, 3, 4])
    assert secrets != None 

    subscrption = gen_subscription(secrets, 0xdeadbeef, 1, 128, 1)
    assert subscrption != None

def test_encoder() :
    secrets = gen_secrets([1, 2, 3, 4])
    assert secrets != None 

    secrets_json = json.loads(secrets)
    print("\n===== secrets =====")
    print("KVe", secrets_json['video']['key'])
    print("KVi", secrets_json['video']['iv'])
    print("KVa", secrets_json['video']['auth'])
    print("KSe", secrets_json['subscription']['key'])
    print("KSi", secrets_json['subscription']['iv'])
    print("KSa", secrets_json['subscription']['auth'])

    subscrption = gen_subscription(secrets, 0xdeadbeef, 1, 128, 1)
    print("\n===== subscrption =====\n", subscrption)
    assert subscrption != None

    encoder = Encoder(secrets)
    assert encoder != None

    cipher_text = encoder.encode(1, b'Hello World', 1245)
    print("\n===== cipher_text =====\n", cipher_text)
    assert cipher_text != None