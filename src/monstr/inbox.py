import hashlib
import json
from monstr.encrypt import Keys
from monstr.signing import SignerInterface
from monstr.event.event import Event
from monstr.util import util_funcs


class Inbox:

    """
        an inbox is a standard account that is used for wrapping other messages in so that only those that
        have the priv_k to the inbox can see.
        It can be watched via looking for messages with the same pub_k and kind (default kind4)
        When using encrypted messages over the inbox they can only be encrypted if you know the shared key,
        so you need to know which pubkeys you might expect messages from.
        The shared key is added to the wrapping event as shared tag

        TODO - support use of NIP44 for the encryption

    """

    @staticmethod
    async def generate_share_key(for_sign: SignerInterface, to_pub_k: str) -> str:
        # TODO: the shared key is sha256(echd_key) of for_sign to to_key
        #  this is the same as the how clust did it - maybe though we should add
        #  in something from the inbox so that the share key for 2 people will be
        #  different per inbox?
        echd_key = await for_sign.echd_key(to_pub_k)
        return hashlib.sha256(echd_key.encode()).hexdigest()

    def __init__(self,
                 signer: SignerInterface,
                 name: str=None,
                 use_kind=Event.KIND_ENCRYPT):

        # key pair for the inbox
        self._signer = signer

        # a printable name for us, if not given just the hex pubkey
        self._name = name

        # the kind we'll be setting the wrapping events to, default is 4
        self._kind = use_kind

        # make up the share map - needed if passing encrypted messages over inbox
        # make sure to call set_share_map to generate the mappings or no encrypted messages can be
        # decrypted
        self._share_maps = {}

    async def set_share_map(self, for_sign: SignerInterface, to_keys: [Keys | str]):
        n_map = {}
        for k in to_keys:
            if isinstance(k, Keys):
                k = k.public_key_hex()
            n_map[await Inbox.generate_share_key(for_sign=for_sign,
                                                 to_pub_k=k)] = k
        self._share_maps[await for_sign.get_public_key()] = n_map

    @property
    async def name(self) -> str:
        if self._name:
            ret = self._name
        # default name is trim of pub k if not given
        else:
            ret = self._name = util_funcs.str_tails(await self._signer.get_public_key())

        return ret

    @property
    async def pub_key(self) -> str:
        return await self._signer.get_public_key()

    @property
    def kind(self) -> int:
        return self._kind

    async def wrap_event(self, evt, from_sign: SignerInterface = None, to_k: Keys | str = None) -> Event:
        tags = []
        if to_k and isinstance(to_k, Keys):
            to_k = to_k.public_key_hex()

        # if supplied the we're going to encrypt, we'll generate a share key that should only possible
        # for from_k and to_k to derive
        # this key is how we know a mesage is for/from us in future
        shared_key = None
        if from_sign and to_k:
            shared_key = await self.generate_share_key(for_sign=from_sign,
                                                       to_pub_k=to_k)
            tags.append(['shared', shared_key])

        evt = Event(kind=self.kind,
                    content=json.dumps(evt.data()),
                    pub_key=await self.pub_key,
                    tags=tags)

        if shared_key:
            evt.content = await from_sign.nip4_encrypt(plain_text=evt.content,
                                                       to_pub_k=to_k)
        else:
            evt.content = await self._signer.nip4_encrypt(plain_text=evt.content,
                                                          to_pub_k=await self.pub_key)

        await self._signer.sign_event(evt)

        return evt

    async def unwrap_event(self, evt: Event, user_sign: SignerInterface):
        ret = None
        shared = evt.get_tag_value_pos('shared')

        # its a shared its encrypted for a specific user is that us
        if shared and user_sign:
            user_pub_k = await user_sign.get_public_key()

            # if us we'll try and unwrap, otherwise we'll just ret None - not for us?...
            share_map = {}

            if user_pub_k in self._share_maps:
                share_map = self._share_maps[user_pub_k]
            if shared in share_map:
                try:
                    content = await user_sign.nip4_decrypt(payload=evt.content,
                                                           for_pub_k=share_map[shared])

                    ret = Event.load(content)
                except Exception as e:
                    pass
        # we'll just treat it as standard
        else:
            try:
                content = await self._signer.nip4_decrypt(payload=evt.content,
                                                          for_pub_k=await self.pub_key)
                ret = Event.load(content)
            except Exception as e:
                pass
        return ret
