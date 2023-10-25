import hashlib
import json
from monstr.encrypt import SharedEncrypt, Keys
from monstr.event.event import Event


class Inbox:

    """
        an inbox is a standard account that is used for wrapping other messages in so that only those that
        have the priv_k to the inbox can see.
        It can be watched via looking for messages with the same pub_k and kind (default kind4)
        When using encrypted messages over the inbox they can only be encrypted if you know the shared key,
        so you need to know which pubkeys you might expect messages from.
        The shared key is added to the wrapping event as shared tag


    """

    @staticmethod
    def generate_share_key(for_keys: Keys, to_keys: Keys | str) -> str:
        # generate the share key, this will be added to decrypted messages and can only
        # be derived between from_user and to_user
        # TODO: maybe we should add an inbox component so that it will be different on each inbox?
        se = SharedEncrypt(priv_k_hex=for_keys.private_key_hex())

        if isinstance(to_keys, Keys):
            to_keys = to_keys.public_key_hex()

        echd_key = se.derive_shared_key(pub_key_hex=to_keys)
        return hashlib.sha256(echd_key.encode()).hexdigest()

    def __init__(self,
                 keys: Keys,
                 name: str=None,
                 use_kind=Event.KIND_ENCRYPT):

        # key pair for the inbox
        self._keys = keys

        # a printable name for us, if not given just the hex pubkey
        self._name = name

        # the kind we'll be setting the wrapping events to, default is 4
        self._kind = use_kind

        # make up the share map - needed if passing encrypted messages over inbox
        # make sure to call set_share_map to generate the mappings or no encrypted messages can be
        # decrypted
        self._share_maps = {}

    def set_share_map(self, for_keys: Keys, to_keys: [Keys | str]):
        n_map = {}
        for k in to_keys:
            if isinstance(k, Keys):
                k = k.public_key_hex()
            n_map[Inbox.generate_share_key(for_keys=for_keys,
                                           to_keys=k)] = k

        self._share_maps[for_keys.public_key_hex()] = n_map

    @property
    def name(self) -> str:
        ret = self._keys.public_key_hex()
        if self._name:
            ret = self._name
        return ret

    @property
    def view_key(self) -> str:
        return self._keys.public_key_hex()

    @property
    def decrypt_key(self) -> str:
        return self._keys.private_key_hex()

    @property
    def kind(self) -> int:
        return self._kind

    def wrap_event(self, evt, from_k: Keys = None, to_k: Keys | str = None):
        tags = []
        if to_k and isinstance(to_k, Keys):
            to_k = to_k.public_key_hex()


        # if supplied the we're going to encrypt, we'll generate a share key that should only possible
        # for from_k and to_k to derive
        # this key is how we know a mesage is for/from us in future
        shared_key = None
        if from_k and to_k:
            shared_key = self.generate_share_key(from_k, to_k)
            tags.append(['shared', shared_key])

        evt = Event(kind=self.kind,
                    content=json.dumps(evt.event_data()),
                    pub_key=self.view_key,
                    tags=tags)

        if shared_key:
            evt.content = evt.encrypt_content(from_k.private_key_hex(), to_k)
        else:
            evt.content = evt.encrypt_content(self.decrypt_key, self.view_key)

        evt.sign(self.decrypt_key)

        return evt

    def unwrap_event(self, evt: Event, keys: Keys=None):
        ret = None
        shared = evt.get_tag_value_pos('shared')

        # its a shared its encrypted for a specific user is that us
        if shared and keys:
            # if us we'll try and unwrap, otherwise we'll just ret None - not for us?...
            share_map = {}

            if keys.public_key_hex() in self._share_maps:
                share_map = self._share_maps[keys.public_key_hex()]

            if shared in share_map:
                try:
                    content = evt.decrypted_content(priv_key=keys.private_key_hex(),
                                                    pub_key=share_map[shared],
                                                    check_kind=False)
                    ret = Event.from_JSON(json.loads(content))
                except Exception as e:
                    pass
        # we'll just treat it as standard
        else:
            try:
                content = evt.decrypted_content(self.decrypt_key, self.view_key, check_kind=False)
                ret = Event.from_JSON(json.loads(content))
            except Exception as e:
                pass
        return ret
