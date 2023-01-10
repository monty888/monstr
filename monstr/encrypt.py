"""
    code to support encrpted notes using ECDH as NIP4
"""

# FIXME: chenage to use cipher from cryptography so we dont need both Crypto and cryptography
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import secp256k1
import bech32
from enum import Enum


# TODO: sort something out about the different key formats....
class KeyEnc(Enum):
    BYTES = 1
    HEX = 2


class Keys:

    @staticmethod
    def get_new_key_pair(priv_key=None):
        """
        :param priv_key: private key in hex str format
        where priv_key is not supplied a new priv key is generated

        :return:
        {
            priv_k : hex_str
            pub_k : hex_str
        }
        """
        if priv_key is None:
            pk = secp256k1.PrivateKey()
        else:
            pk = secp256k1.PrivateKey(bytes(bytearray.fromhex(priv_key)), raw=True)

        return {
            'priv_k': pk.serialize(),
            # get rid of 02 prefix that is assumed in monstr
            'pub_k': pk.pubkey.serialize(compressed=True).hex()[2:]
        }

    @staticmethod
    def is_valid_key(key:str):
        """
            returns true if key is any of hex/npub/nsec and looks correct
        """
        return Keys.is_hex_key(key) or Keys.is_bech32_key(key)

    @staticmethod
    def is_hex_key(key:str):
        """
            returns true if looks like valid hex string for monstr key its not possible to tell if priv/pub
        """
        ret = False
        if len(key) == 64:
            # and also hex, will throw otherwise
            try:
                bytearray.fromhex(key)
                ret = True
            except:
                pass
        return ret

    @staticmethod
    def is_bech32_key(key:str):
        ret = False
        key = key.lower()
        if key.startswith('npub') or key.startswith('nsec'):
            try:
                Keys.bech32_to_hex(key)
                ret = True
            except:
                pass

        return ret

    @staticmethod
    def hex_to_bech32(key_str: str, prefix='npub'):
        as_int = [int(key_str[i:i+2], 16) for i in range(0, len(key_str), 2)]
        data = bech32.convertbits(as_int, 8, 5)
        return bech32.bech32_encode(prefix, data)

    @staticmethod
    def bech32_to_hex(key: str):
        # should be the reverese of hex_to_bech32...
        as_int = bech32.bech32_decode(key)
        data = bech32.convertbits(as_int[1], 5, 8)
        return ''.join([hex(i).replace('0x', '').rjust(2,'0') for i in data][:32])

    @staticmethod
    def hex_key(key: str)-> str:
        """
        :param key: can be hex/npub/nsec and you'll get back the hex rep
        if doesn't look like valid key then None will be returned
        :return:
        """
        ret = None
        if Keys.is_hex_key(key):
            ret = key
        elif Keys.is_bech32_key(key):
            ret = Keys.bech32_to_hex(key)

        return ret

    @staticmethod
    def get_key(key: str):
        """
        returns a key object from the given str, npub/nsec will be used correctly if hex it'll only be used as a
        public key.
        where npub/hex is supplied the Keys objects will return None for private_key methods
        if the key str doesn't look valid None is returned
        """
        ret = None
        key = key.lower()
        if Keys.is_valid_key(key):
            if key.startswith('nsec'):
                ret = Keys(priv_k=key)
            else:
                ret = Keys(pub_k=key)
        return ret

    def __init__(self, priv_k: str=None, pub_k: str=None):
        """
        :param priv_k: hex/nsec
        :param pub_k: hex/npub

        If no keys supplied then a new key pair will be generated
        supplied keys can be in either hex/npub/nsec format, internally we keep then as hex
        if both pub_k and priv_k are supplied then the pub_k will be checked to see that it matches but doesn't seem
        any reason while you'd supply both
        if no priv_k is supplied the private key methods will just return None
        """

        # internal hex format
        self._priv_k= None
        self._pub_k = None

        # nothing supplied generate new keys
        if priv_k is None and pub_k is None:
            k_pair = self.get_new_key_pair()
            self._priv_k = k_pair['priv_k']
            self._pub_k = k_pair['pub_k']
        elif priv_k:
            if Keys.is_bech32_key(priv_k):
                if priv_k.startswith('npub'):
                    raise Exception('attempt to use npub as private key!!')
                priv_k = Keys.hex_key(priv_k)
            k_pair = self.get_new_key_pair(priv_k)
            if pub_k and k_pair[pub_k] != pub_k:
                raise Exception('attempt to create key with mismatched keypair, maybe just don\'t supply the pub_k?')
            self._pub_k = k_pair['pub_k']
            self._priv_k = k_pair['priv_k']
        # only pub_k supplied, won't be able to sign
        else:
            self._pub_k = Keys.hex_key(pub_k)
            if not self._pub_k:
                raise Exception('pub_k does\'t look like a valid monstr key - %s' % pub_k)

    def private_key_hex(self):
        return self._priv_k

    def private_key_bech32(self):
        ret = None
        if self._priv_k:
            ret = self.hex_to_bech32(self._priv_k, 'nsec')
        return ret

    def public_key_hex(self):
        return self._pub_k

    def public_key_bech32(self):
        ret = None
        if self._pub_k:
            ret = self.hex_to_bech32(self._pub_k)
        return ret

    def __str__(self):
        ret = []
        if self.private_key_hex():
            ret.append('**private**')
            ret.append('%s%s' % ('hex'.ljust(10),
                                 self.private_key_hex()))
            ret.append('%s%s' % ('bech32'.ljust(10),
                                 self.private_key_bech32()))

        ret.append('**public**')
        ret.append('%s%s' % ('hex'.ljust(10),
                             self.public_key_hex()))
        ret.append('%s%s' % ('bech32'.ljust(10),
                             self.public_key_bech32()))
        return '\n'.join(ret)

class SharedEncrypt:

    def __init__(self, priv_k_hex):
        """
        :param priv_k_hex:              our private key
        TODO: take a look at priv_k and try to create and work out from it

        """

        # us, hex, int and key
        self._priv_hex = priv_k_hex
        self._priv_int = int(priv_k_hex, 16)
        self._key = ec.derive_private_key(self._priv_int, ec.SECP256K1())
        # our public key for priv key
        self._pub_key = self._key.public_key()
        # shared key for priv/pub ECDH
        self._shared_key = None

    @property
    def public_key_hex(self):
        return self.public_key_bytes.hex()

    @property
    def public_key_bytes(self):
        return self._pub_key.public_bytes(encoding=serialization.Encoding.X962,
                                          format=serialization.PublicFormat.CompressedPoint)

    def derive_shared_key(self, pub_key_hex, as_type=KeyEnc.HEX):
        pk = secp256k1.PublicKey()
        if len(pub_key_hex) == 64:
            pub_key_hex = '02' + pub_key_hex

        pk.deserialize(bytes.fromhex(pub_key_hex))
        pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk.serialize(False))
        self._shared_key = self._key.exchange(ec.ECDH(), pub_key)

        # added return so we don't have to do as 2 step all the time
        return self.shared_key(as_type)

    def shared_key(self, as_type=KeyEnc.HEX):
        if self._shared_key is None:
            raise Exception('SharedEncrypt::shared_key hasn\'t been derived yet')

        ret = self._shared_key
        if as_type == KeyEnc.HEX:
            ret = self._shared_key.hex()

        return ret

    def encrypt_message(self, data, pub_key_hex=None):
        if pub_key_hex is not None:
            self.derive_shared_key(pub_key_hex)

        key = secp256k1.PrivateKey().deserialize(self.shared_key(as_type=KeyEnc.HEX))
        # iv = get_random_bytes(16)
        iv = os.urandom(16)
        # data = Padding.pad(data, 16)
        padder = padding.PKCS7(128).padder()
        data = padder.update(data)
        data += padder.finalize()

        # cipher = AES.new(key, AES.MODE_CBC, iv)
        ciper = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = ciper.encryptor()

        return {
            'text': encryptor.update(data) + encryptor.finalize(),
            'iv': iv,
            'shared_key': self._shared_key
        }

    def decrypt_message(self, encrypted_data,iv, pub_key_hex=None):
        if pub_key_hex is not None:
            self.derive_shared_key(pub_key_hex)

        key = secp256k1.PrivateKey().deserialize(self.shared_key(as_type=KeyEnc.HEX))
        ciper = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = ciper.decryptor()

        ret = decryptor.update(encrypted_data)
        padder = padding.PKCS7(128).unpadder()
        ret = padder.update(ret)
        ret += padder.finalize()

        return ret