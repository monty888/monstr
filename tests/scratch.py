import secp256k1
from hashlib import sha256
import hmac
from monstr.event.event import Event


def nip4_event_encrypt_decrypt(content: str):
    test_evt = Event(content=content)
    test


test_text = 'test message for mr monty!!!!'
nip4_event_encrypt_decrypt(test_text)
