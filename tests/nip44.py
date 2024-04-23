import asyncio
import secp256k1
from hashlib import sha256
import hmac
from monstr.event.event import Event
from monstr.encrypt import Keys
# from monstr.signing import BasicKeySigner, SignerInterface
from src.monstr.signing import SignerInterface, BasicKeySigner

async def make_nip44_event():
    await nip44_encrypt_payload('some content for the event')

def hmac_digest(key: bytes, data: bytes, hash_function) -> bytes:
    return hmac.new(key, data, hash_function).digest()

def hkdf_extract(salt: bytes, ikm: bytes, hash_function) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function.digest_size)
    return hmac_digest(salt, ikm,hash_function)


def get_conversion_key(priv_k: str, to_pub_k: str):

    the_priv: secp256k1.PrivateKey = secp256k1.PrivateKey(privkey=bytes.fromhex(priv_k))
    print(f'using priv: {the_priv.private_key.hex()}')

    the_pub: secp256k1.PublicKey = secp256k1.PublicKey(pubkey=bytes.fromhex('02'+to_pub_k), raw=True)
    print(f'using pub_k: {the_pub.serialize().hex()}')

    tweaked_key: secp256k1.PublicKey = the_pub.tweak_mul(the_priv.private_key)

    print(f'tweaked {tweaked_key.serialize().hex()}')

    ret = hkdf_extract(salt=b'nip44-v2',
                       ikm=tweaked_key.serialize()[1:],
                       hash_function=sha256)

    print(f'conversion key: {ret.hex()}')
    return ret

async def nip44_encrypt_payload(payload: str, version=2):
    # testing for ...., then make use test case file
    # "sec1": "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
    # "pub2": "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
    # "conversation_key": "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"

    priv_k = 'df2f560e213ca5fb33b9ecde771c7c0cbd30f1cf43c2c24de54480069d9ab0af'
    pub_k= 'eeea26e552fc8b5e377acaa03e47daa2d7b0c787fac1e0774c9504d9094c430e'

    k = Keys(priv_k=priv_k)
    my_sign:SignerInterface = BasicKeySigner(key=k)



    # get_conversion_key(priv_k=priv_k, to_pub_k=pub_k)
    test_msg = 'SOME TEST TEXT!!!'


    payload = await my_sign.nip44_encrypt(plain_text=test_msg,
                                             to_pub_k=pub_k)

    print(f'nip44 payload: {payload}')

    plain_text = await my_sign.nip44_decrypt(payload=payload,
                                             for_pub_k=pub_k)

    print(f'nip44 plain text: {plain_text}')

    payload = await my_sign.nip4_encrypt(plain_text=plain_text,
                                         to_pub_k=pub_k)

    print(f'nip 4 payload: {payload}')

    plain_text = await my_sign.nip4_decrypt(payload=payload,
                                            for_pub_k=pub_k)

    print(f'nip4 plain text: {plain_text}')


if __name__ == '__main__':
    asyncio.run(make_nip44_event())


