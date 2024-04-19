import secp256k1
from hashlib import sha256
import hmac


def hmac_digest(key: bytes, data: bytes, hash_function) -> bytes:
    return hmac.new(key, data, hash_function).digest()


def hkdf_extract(salt: bytes, ikm: bytes, hash_function) -> bytes:
    if len(salt) == 0:
        salt = bytes([0] * hash_function.digest_size)
    return hmac_digest(salt, ikm,hash_function)

def get_conversion_key(priv_k:str, pub_k:str):

    the_priv: secp256k1.PrivateKey = secp256k1.PrivateKey(privkey=bytes.fromhex(priv_k))
    print(f'using priv: {the_priv.private_key.hex()}')

    the_pub: secp256k1.PublicKey = secp256k1.PublicKey(pubkey=bytes.fromhex('02'+pub_k), raw=True)
    print(f'using pub_k: {the_pub.serialize().hex()}')

    tweaked_key: secp256k1.PublicKey = the_pub.tweak_mul(the_priv.private_key)

    print(f'tweaked {tweaked_key.serialize().hex()}')


    con_key = hkdf_extract(salt=b'nip44-v2',
                           ikm=tweaked_key.serialize()[1:],
                           hash_function=sha256)

    print(f'conversion k: {con_key.hex()}')

def get_conversion_key2(priv_k:str, pub_k:str):

    the_priv: secp256k1.PrivateKey = secp256k1.PrivateKey(privkey=bytes.fromhex(priv_k))
    print(f'using priv: {the_priv.private_key.hex()}')

    the_pub: secp256k1.PublicKey = secp256k1.PublicKey(pubkey=bytes.fromhex('02'+pub_k), raw=True)
    print(f'using pub_k: {the_pub.serialize().hex()}')

    tweaked_key: secp256k1.PublicKey = the_pub.tweak_mul(the_priv.private_key)

    print(f'tweaked {tweaked_key.serialize().hex()}')

    hdf = hkdf(
        salt=b'nip44-v2',
        ikm=tweaked_key.serialize(),
        info=b'',
        length=32,
    )

    print(hdf.hex())



get_conversion_key(priv_k='a1e37752c9fdc1273be53f68c5f74be7c8905728e8de75800b94262f9497c86e',
                    pub_k='03bb7947065dde12ba991ea045132581d0954f042c84e06d8c00066e23c1a800')
print('****')
get_conversion_key2(priv_k='315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268',
                    pub_k='c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133')


