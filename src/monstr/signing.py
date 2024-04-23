from abc import abstractmethod
from hashlib import sha256
from monstr.event.event import Event
from monstr.encrypt import Keys
from src.monstr.encrypt import NIP44Encrypt, NIP4Encrypt


class SignerInterface:

    @abstractmethod
    async def get_public_key(self) -> str:
        pass

    @abstractmethod
    async def sign_event(self, evt: Event):
        pass

    @abstractmethod
    async def echd_key(self, to_key: str) -> str:
        pass

    @abstractmethod
    async def nip4_encrypt(self, plain_text: str, to_pub_k: str) -> str:
        raise NotImplementedError('nip4 encryption not implemented for this signer')

    @abstractmethod
    async def nip4_decrypt(self, cipher_text: str, for_pub_k: str) -> str:
        raise NotImplementedError('nip4 encryption not implemented for this signer')

    @abstractmethod
    async def nip4_decrypt_event(self, evt: Event) -> Event:
        raise NotImplementedError('nip4 encryption not implemented for this signer')

    @abstractmethod
    async def nip44_encrypt(self, plain_text: str, to_pub_k: str, version=2) -> str:
        raise NotImplementedError('nip44 encryption not implemented for this signer')

    @abstractmethod
    async def nip44_decrypt(self, payload: str, for_pub_k: str) -> str:
        raise NotImplementedError('nip44 encryption not implemented for this signer')


class BasicKeySigner(SignerInterface):

    def __init__(self, key: Keys):
        if key.private_key_hex() is None:
            raise ValueError('BasicKeySigner:: a key that can sign is required')

        self._keys = key

        # for implementing nip44, v2 is supported only
        # see https://github.com/paulmillr/nip44
        self._nip44_hash_func = sha256
        self._nip44_salt = b'nip44-v2'

        self._nip4_encrypt = NIP4Encrypt(key=self._keys)
        self._nip44_encrypt = NIP44Encrypt(key=self._keys)

    async def get_public_key(self) -> str:
        return self._keys.public_key_hex()

    async def sign_event(self, evt: Event):
        evt.sign(self._keys.private_key_hex())

    async def echd_key(self, to_pub_k: str) -> str:
        return self._nip4_encrypt.get_echd_key_hex(to_pub_k)

    async def nip4_encrypt(self, plain_text: str, to_pub_k: str) -> str:
        return self._nip4_encrypt.encrypt(plain_text=plain_text,
                                          to_pub_k=to_pub_k)

    async def nip4_decrypt(self, payload: str, for_pub_k: str) -> str:
        return self._nip4_encrypt.decrypt(payload=payload,
                                          for_pub_k=for_pub_k)

    async def nip4_decrypt_event(self, evt: Event) -> Event:
        return self._nip4_encrypt.nip4_decrypt_event(evt)

    async def nip44_encrypt(self, plain_text: str, to_pub_k: str, version=2) -> str:
        return self._nip44_encrypt.encrypt(plain_text=plain_text,
                                                 to_pub_k=to_pub_k,
                                                 version=version)

    async def nip44_decrypt(self, payload: str, for_pub_k: str, version=2) -> str:
        return self._nip44_encrypt.decrypt(payload=payload,
                                           for_pub_k=for_pub_k,
                                           version=version)







