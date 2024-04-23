"""
    code to support encrpted notes using ECDH as NIP4
"""
import encodings.utf_8
import os
from hashlib import sha256
import hmac
from math import floor, log2
import base64
from Crypto.Cipher import ChaCha20, AES
from Crypto.Util.Padding import pad, unpad
# from Crypto.PublicKey import ECC
# unfortunately we need this both crypto libs to as PyCryptodome doesn't seem to support sep256k1
# and cryptograpy.io doesn't have Chacha without the mac that we need for NIP44 as far as I could understand it
from cryptography.hazmat.primitives.asymmetric import ec

import secp256k1
import bech32
from enum import Enum
from monstr.event.event import Event


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

        # if already a key object just return as is
        if isinstance(key, Keys):
            return key

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
        self._priv_k = None
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
            if pub_k and k_pair['pub_k'] != pub_k:
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


# class SharedEncrypt:
#     # TODO - to be removed ...., replace either using NIP4 class directly or use signer
#     def __init__(self, priv_k_hex):
#         """
#         :param priv_k_hex:              our private key
#         TODO: take a look at priv_k and try to create and work out from it
#
#         """
#
#         # us, hex, int and key
#         self._priv_hex = priv_k_hex
#         self._priv_int = int(priv_k_hex, 16)
#         self._key = ec.derive_private_key(self._priv_int, ec.SECP256K1())
#         # our public key for priv key
#         self._pub_key = self._key.public_key()
#         # shared key for priv/pub ECDH
#         self._shared_keys = {}
#
#     @property
#     def public_key_hex(self):
#         return self.public_key_bytes.hex()
#
#     @property
#     def public_key_bytes(self):
#         return self._pub_key.public_bytes(encoding=serialization.Encoding.X962,
#                                           format=serialization.PublicFormat.CompressedPoint)
#
#     def _get_derived_shared_key(self, to_pub_k: str):
#         # first time we need to derive the shared key for us and the pub_k
#         if to_pub_k not in self._shared_keys:
#             pk = secp256k1.PublicKey()
#             pk.deserialize(bytes.fromhex('02'+to_pub_k))
#             ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk.serialize(False))
#             shared_key = self._key.exchange(ec.ECDH(), ec_key)
#
#             self._shared_keys[to_pub_k] = {
#                 KeyEnc.BYTES: shared_key,
#                 KeyEnc.HEX: shared_key.hex()
#             }
#
#     def get_echd_key_hex(self, to_pub_k: str) -> str:
#         self._get_derived_shared_key(to_pub_k=to_pub_k)
#         return self._shared_keys[to_pub_k][KeyEnc.HEX]
#
#     def encrypt_message(self, data, to_pub_k: str):
#         share_key = self.get_echd_key_hex(to_pub_k)
#         key = secp256k1.PrivateKey().deserialize(share_key)
#         # iv = get_random_bytes(16)
#         iv = os.urandom(16)
#         # data = Padding.pad(data, 16)
#         padder = padding.PKCS7(128).padder()
#         data = padder.update(data)
#         data += padder.finalize()
#         # cipher = AES.new(key, AES.MODE_CBC, iv)
#         ciper = Cipher(algorithms.AES(key), modes.CBC(iv))
#         encryptor = ciper.encryptor()
#         return {
#             'text': encryptor.update(data) + encryptor.finalize(),
#             'iv': iv,
#             'shared_key': share_key
#         }
#
#     def decrypt_message(self, encrypted_data, iv, to_pub_k: str):
#         share_key = self.get_echd_key_hex(to_pub_k=to_pub_k)
#
#         key = secp256k1.PrivateKey().deserialize(share_key)
#         ciper = Cipher(algorithms.AES(key), modes.CBC(iv))
#         decryptor = ciper.decryptor()
#
#         ret = decryptor.update(encrypted_data)
#         padder = padding.PKCS7(128).unpadder()
#         ret = padder.update(ret)
#         ret += padder.finalize()
#
#         return ret


class NIP4Encrypt:

    def __init__(self, key: Keys | str):
        if isinstance(key, str):
            key = Keys(priv_k=key)
        if key.private_key_hex() is None:
            raise ValueError('NIP4Encrypt:: a key that can sign is required')

        self._keys = key
        self._priv_k = secp256k1.PrivateKey(bytes.fromhex(self._keys.private_key_hex()))

        # self._priv_int = int(priv_k_hex, 16)

        self._ec_key = ec.derive_private_key(int.from_bytes(self._priv_k.private_key,byteorder='big'), ec.SECP256K1())

        # shared key for priv/pub ECDH
        self._shared_keys = {}

    def _get_derived_shared_key(self, to_pub_k: str):
        # first time we need to derive the shared key for us and the pub_k
        if to_pub_k not in self._shared_keys:
            pk = secp256k1.PublicKey()
            pk.deserialize(bytes.fromhex('02'+to_pub_k))
            ec_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pk.serialize(False))
            shared_key = self._ec_key.exchange(ec.ECDH(), ec_key)

            self._shared_keys[to_pub_k] = {
                KeyEnc.BYTES: shared_key,
                KeyEnc.HEX: shared_key.hex()
            }

    def get_echd_key_hex(self, to_pub_k: str) -> str:
        self._get_derived_shared_key(to_pub_k=to_pub_k)
        return self._shared_keys[to_pub_k][KeyEnc.HEX]

    def _do_encrypt(self, plain_text: str, to_pub_k: str):
        data = bytes(plain_text.encode('utf8'))
        share_key = self.get_echd_key_hex(to_pub_k)
        key = secp256k1.PrivateKey().deserialize(share_key)

        iv = os.urandom(16)
        data = pad(data, block_size=16, style='pkcs7')
        ciper = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
        ciper_text = ciper.encrypt(data)

        return {
            'text': ciper_text,
            'iv': iv,
            'shared_key': share_key
        }

    def encrypt(self, plain_text: str, to_pub_k: str) -> str:
        crypt_message = self._do_encrypt(plain_text=plain_text,
                                         to_pub_k=to_pub_k)
        enc_message = base64.b64encode(crypt_message['text'])
        iv_env = base64.b64encode(crypt_message['iv'])
        return f'{enc_message.decode()}?iv={iv_env.decode()}'

    def _do_decrypt(self, encrypted_data, iv, to_pub_k: str):
        share_key = self.get_echd_key_hex(to_pub_k=to_pub_k)

        key = secp256k1.PrivateKey().deserialize(share_key)
        ciper = AES.new(key=key,
                        mode=AES.MODE_CBC,
                        iv=iv)
        padded = ciper.decrypt(encrypted_data)
        return unpad(padded, block_size=16, style='pkcs7')

    def decrypt(self, payload: str, for_pub_k: str) -> str:
        msg_split = payload.split('?iv')
        text = base64.b64decode(msg_split[0])
        iv = base64.b64decode(msg_split[1])
        return self._do_decrypt(encrypted_data=text,
                                iv=iv,
                                to_pub_k=for_pub_k).decode('utf8')

    def decrypt_event(self, evt: Event) -> Event:
        """
            util method for decrypting basic nip4 encrypted events
        """
        pub_k = evt.pub_key
        if pub_k == self._keys.private_key_hex():
            pub_k = evt.p_tags[0]

        ret = Event.from_JSON(evt.event_data())
        ret.content = self.decrypt(payload=evt.content,
                                   for_pub_k=pub_k)
        return ret


class NIP44Encrypt:
    """
        base functionality for implementing NIP44
        https://github.com/paulmillr/nip44
    """

    NIP44_PAD_MIN = 1
    NIP44_PAD_MAX = 65535

    def __init__(self, key: Keys | str):
        if isinstance(key, str):
            key = Keys(priv_k=key)

        if key.private_key_hex() is None:
            raise ValueError('NIP44Encrypt:: a key that can sign is required')

        self._keys = key
        self._priv_k = secp256k1.PrivateKey(bytes.fromhex(self._keys.private_key_hex()))

        # we only support v2 which is sha256 hash and this *-v2 salt
        self._nip44_hash_func = sha256
        self._nip44_salt = b'nip44-v2'

    # hkdf functions taken and modified from https://en.wikipedia.org/wiki/HKDF 14/4/2024
    @staticmethod
    def _hmac_digest(key: bytes, data: bytes, hash_func) -> bytes:
        return hmac.new(key, data, hash_func).digest()

    @staticmethod
    def _hkdf_extract(salt: bytes, ikm: bytes, hash_function) -> bytes:
        if len(salt) == 0:
            salt = bytes([0] * hash_function.digest_size)
        return NIP44Encrypt._hmac_digest(salt, ikm, hash_function)

    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int, hashfunction) -> bytes:
        t = b""
        okm = b""
        i = 0
        while len(okm) < length:
            i += 1
            t = NIP44Encrypt._hmac_digest(prk, t + info + bytes([i]), hashfunction)
            okm += t
        return okm[:length]

    @staticmethod
    def _hmac_aad(key, message, aad, hash_function) -> bytes:
        print('hmac_add', key.hex(), message.hex(), aad.hex())


        if len(aad) != 32: raise Exception('AAD associated data must be 32 bytes');
        return NIP44Encrypt._hmac_digest(key=key,
                                         data=aad+message,
                                         hash_func=hash_function)

    @staticmethod
    def _calc_padded_len(unpadded_len):
        next_power = 32
        if unpadded_len > 1:
            next_power = (floor(log2(unpadded_len - 1))) + 1

        if next_power <= 256:
            chunk = 32
        else:
            chunk = next_power / 8
        if unpadded_len <= 32:
            return 32
        else:
            return chunk * (floor((len - 1) / chunk) + 1)

    @staticmethod
    def _pad(plaintext: str) -> bytes:
        plaintext = plaintext.encode('utf-8')
        unpadded_len = len(plaintext)

        if (unpadded_len < NIP44Encrypt.NIP44_PAD_MIN or unpadded_len > NIP44Encrypt.NIP44_PAD_MAX):
            raise Exception('invalid plaintext length')

        padded_length = NIP44Encrypt._calc_padded_len(unpadded_len)

        prefix = unpadded_len.to_bytes(length=2, byteorder='big', signed=False)
        sufix = bytes(padded_length-unpadded_len)

        return prefix+plaintext+sufix

    @staticmethod
    def _unpad(padded: bytes) -> bytes:
        msg_len = int.from_bytes(padded[:2],byteorder='big')
        ret = padded[2:msg_len+2]

        if msg_len == 0 \
                or len(ret) != msg_len \
                or NIP44Encrypt._calc_padded_len(len(ret))+2 != len(padded):

            raise Exception('nip44 invalid padding')

        return ret

    @staticmethod
    def _decode_payload(payload) -> tuple[bytes, bytes, bytes]:
        p_size = len(payload)

        # TODO: size limits should be being calculated from MIN/MAX PAD
        if p_size < 132 or p_size > 87472:
            raise Exception(f'invalid payload size {p_size}')

        data = base64.b64decode(payload)
        d_size = len(data)

        if d_size < 99 or d_size > 65603:
            raise Exception(f'invalid payload size {p_size}')

        version = data[0]
        nonce = data[1:33]
        cipher_text = data[33:d_size-32]
        mac = data[d_size-32:]

        # only current/supported version
        if version != 2:
            raise ValueError(f'nip44_encrypt unsupported version {version}')

        return nonce, cipher_text, mac

    def _nip44_get_conversion_key(self, for_pub_k: str) -> bytes:
        the_pub: secp256k1.PublicKey = secp256k1.PublicKey(pubkey=bytes.fromhex('02' + for_pub_k), raw=True)

        # Execute ECDH mult for shared key
        tweaked_key: secp256k1.PublicKey = the_pub.tweak_mul(self._priv_k.private_key)

        return NIP44Encrypt._hkdf_extract(salt=self._nip44_salt,
                                          ikm=tweaked_key.serialize()[1:],
                                          hash_function=self._nip44_hash_func)

    def _nip44_get_message_key(self, conversion_key: bytes, nonce: bytes = None) -> tuple[bytes, bytes, bytes]:

        if len(nonce) != 32:
            raise ValueError('_nip44_get_message_key nonce is not 32 bytes long')

        msg_key = NIP44Encrypt._hkdf_expand(prk=conversion_key,
                                            info=nonce,
                                            length=76,
                                            hashfunction=self._nip44_hash_func)

        chacha_key = msg_key[0:32]
        chacha_nonce = msg_key[32:44]
        hmac_key = msg_key[44:76]

        return chacha_key, chacha_nonce, hmac_key

    @staticmethod
    def _do_encrypt(padded_data: bytes, key: bytes, nonce: bytes) -> bytes:
        cha = ChaCha20.new(key=key,
                           nonce=nonce)
        return cha.encrypt(padded_data)

    def encrypt(self, plain_text: str, to_pub_k: str, version=2) -> str:
        if version != 2:
            raise ValueError(f'nip44_encrypt unsupported version {version}')

        con_key = self._nip44_get_conversion_key(for_pub_k=to_pub_k)
        nonce = os.urandom(32)

        chacha_key, chacha_nonce, hmac_key = self._nip44_get_message_key(conversion_key=con_key,
                                                                         nonce=nonce)

        padded = self._pad(plain_text)

        cipher_text = NIP44Encrypt._do_encrypt(padded_data=padded,
                                               key=chacha_key,
                                               nonce=chacha_nonce)

        mac = self._hmac_aad(key=hmac_key,
                             message=cipher_text,
                             aad=nonce,
                             hash_function=self._nip44_hash_func)

        payload = version.to_bytes(1,byteorder='big') + nonce + cipher_text + mac

        return base64.b64encode(payload).decode('utf-8')

    @staticmethod
    def _do_decrypt(ciper_text: bytes, key: bytes, nonce: bytes) -> bytes:
        cha = ChaCha20.new(key=key,
                           nonce=nonce)
        return cha.decrypt(ciper_text)

    def decrypt(self, payload: str, for_pub_k: str, version=2) -> str:
        nonce, ciper_text, mac = self._decode_payload(payload)

        con_key = self._nip44_get_conversion_key(for_pub_k)

        chacha_key, chacha_nonce, hmac_key = self._nip44_get_message_key(conversion_key=con_key,
                                                                         nonce=nonce)

        calculated_mac = NIP44Encrypt._hmac_aad(key=hmac_key,
                                                message=ciper_text,
                                                aad=nonce,
                                                hash_function=self._nip44_hash_func)

        if calculated_mac != mac:
            raise ValueError('invalid MAC')

        padded = NIP44Encrypt._do_decrypt(ciper_text=ciper_text,
                                          key=chacha_key,
                                          nonce=chacha_nonce)

        plain_text = NIP44Encrypt._unpad(padded=padded)

        return plain_text.decode('utf-8')