from abc import ABC, abstractmethod
import csv
import logging
from hashlib import sha256
from monstr.encrypt import NIP44Encrypt, Keys, Encrypter
from monstr.db.db import ASQLiteDatabase
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.profile import Profile


class KeyStoreException(Exception):
    pass


class NamedKeys(ABC, Keys):
    """
        Named keys is just a key object with a user defined name
    """
    def __init__(self, name: str, priv_k: str = None, pub_k: str = None):
        self._name = name
        super().__init__(priv_k, pub_k)

    @property
    def name(self)-> str:
        return self._name

    def __str__(self):
        return f'{self._name} - {self.public_key_hex()} , can sign = {self.private_key_hex() is not None}'

    def print_hex(self, include_private=False):
        print(self.public_key_hex())
        if include_private:
            print(self.private_key_hex())

    def print_bech32(self, include_private=False):
        print(self.public_key_bech32())
        if include_private:
            print(self.private_key_bech32())

    def clone(self):
        return NamedKeys(name=self.name,
                         priv_k=self.private_key_hex(),
                         pub_k=self.public_key_hex())


class KeyDataEncrypter:

    def __init__(self,
                 get_key: callable
                 ):
        self._get_key = get_key
        self._enc_key: Keys = None
        self._enc = None

    async def _get_encrypt_key(self) -> Keys:
        if self._enc_key is None:
            key_material = await self._get_key()
            # turn whatever str we got into something we can use as an nsec for encrypting
            key_hex = sha256(key_material.encode('utf-8')).hexdigest()
            self._enc_key = Keys(priv_k=key_hex)
        return self._enc_key

    async def _get_encryptor(self) -> Encrypter:
        if self._enc_key is None:
            k = await self._get_encrypt_key()
            self._enc = NIP44Encrypt(k)
        return self._enc

    async def encrypt_data(self, plain_text: str) -> str:
        enc = await self._get_encryptor()
        return enc.encrypt(plain_text,
                           to_pub_k=self._enc_key.public_key_hex())

    async def decrypt_data(self, payload: str) -> str:
        enc = await self._get_encryptor()
        return enc.decrypt(payload=payload,
                           for_pub_k=self._enc_key.public_key_hex())


class KeystoreInterface(ABC):

    async def convert_memstore(self, old_filename: str):
        """
            this will copy profiles stored in an old style alias file
            (created using alias.py) into this new key_store style
            You can use it also to merge old style into this keystore
            but it will error as soon as it gets a duplicate key name

        """
        old_store = MemoryProfileStore()
        old_store.import_file(old_filename)
        profiles = old_store.select_profiles()
        c_p: Profile
        for c_p in profiles:
            await self.add(NamedKeys(name=c_p.profile_name,
                                     priv_k=c_p.private_key,
                                     pub_k=c_p.public_key))

    @classmethod
    def named_keys(cls, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        ret = k
        if not isinstance(ret, NamedKeys):
            if name is None:
                raise KeyStoreException('FileKeyStore::add: name not supplied')
            ret = NamedKeys(name=name,
                            priv_k=k.private_key_hex(),
                            pub_k=k.public_key_hex())
        else:
            # even in the case of a namedkey we want this obj to be a copy
            ret = ret.clone()

        return ret

    @classmethod
    async def get_store_key(cls, k: NamedKeys, encrypter: KeyDataEncrypter = None) -> str:
        ret = k.private_key_bech32()
        if ret is None:
            ret = k.public_key_bech32()
        if encrypter is not None:
            ret = await encrypter.encrypt_data(ret)
        return ret

    """
        if k is Keys then the name arg is required
    """
    @abstractmethod
    async def add(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        """
            add a new k, name map to the store
            should error if name already exists
        """

    @abstractmethod
    async def update(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        """
            update an existing map in the store
            should error if name does not exist
        """

    @abstractmethod
    async def delete(self, name: str = None) -> NamedKeys:
        """
            delete from store
            should error if name does not exist
        """

    @abstractmethod
    async def get(self, name: str) -> NamedKeys:
        """
            get an existing map from the store, rets None if not found
        """

    @abstractmethod
    async def select(self, filter: list | dict = None) -> [NamedKeys]:
        """
            select op on the store if the filter is None then return all keys
            for now keep this:
                only allow query on name (not npub/nsec)
                the query is always done as an in or *val* -- if you wanted exact you'd use get

            in future it's possible a store might want to limit how many results it returns
            if that is true either we should add iter support? or offset could be used in query
            for now not expect that this store would be massive
        """


class FileKeyStore(KeystoreInterface):
    """
        Keystore interface implemented using a file -
        doubt we'd ever use this in pratice, safer just to use the sqlite version
    """
    def __init__(self,
                 file_name: str,
                 encrypter: KeyDataEncrypter = None):
        self._file_name = file_name
        self._store = None
        self._encrypter = encrypter

    async def _init_store(self):
        if self._store is None:
            try:
                await self.load()
            except FileNotFoundError as fe:
                logging.info(f'FileProfiles::__init__ file doesn\'t exist yet - {self._file_name}')
        return self._store

    async def get(self, name: str) -> NamedKeys:
        ret = None
        # make sure store is loaded
        await self._init_store()

        if name in self._store:
            # return a copy of the one we have stored
            ret = self._store[name].clone()

        return ret

    async def select(self, filter: list | dict = None) -> [NamedKeys]:
        # make sure store is loaded
        await self._init_store()
        ret = [self._store[k] for k in self._store.keys()]
        return ret

    async def add(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        k = self.named_keys(k, name)

        # make sure store is loaded
        await self._init_store()

        if k.name in self._store:
            raise KeyStoreException(f'FileKeyStore::add - {k.name} already exists')

        # in mem
        self._store[k.name] = k
        # and file
        await self._append_store(k)

        return k

    async def update(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        ret = self.named_keys(k, name)

        # make sure store is loaded
        await self._init_store()

        if ret.name not in self._store:
            raise KeyStoreException(f'FileKeyStore::update: not found: {k.name}')

        # in mem
        self._store[ret.name] = ret
        # and file - note requires the whole store to be rewritten!!
        await self.save()

        return ret

    async def delete(self, name: str = None) -> NamedKeys:
        ret = await self.get(name)
        if ret is None:
            raise KeyStoreException(f'FileKeyStore::delete: {name} not found to delete')

        # in mem
        del self._store[ret.name]
        # and file - note requires the whole store to be rewritten!!
        await self.save()

        return ret


    async def save(self, file_name: str = None):
        # nothing to save yet!
        if self._store is None:
            return

        if file_name is None:
            file_name = self._file_name

        with open(file_name, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            kv: NamedKeys
            for name in self._store:
                k = self._store[name]
                kv = k.private_key_bech32()
                if kv is None:
                    kv = k.private_key_bech32()

                writer.writerow([
                    k.name, kv
                ])

    async def load(self, file_name: str = None):
        self._store = {}
        if file_name is None:
            file_name = self._file_name

        nk: NamedKeys
        with open(file_name, 'r', newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                name = row[0]
                key_str = row[1]

                # decrypt if required
                if self._encrypter is not None:
                    key_str = await self._encrypter.decrypt_data(key_str)

                k = Keys.get_key(key_str)

                # looks good
                if k is not None:
                    nk = NamedKeys(name=name,
                                   priv_k=k.private_key_hex(),
                                   pub_k=k.public_key_hex())
                    self._store[name] = nk
                else:
                    logging.debug(f'FileKeyStore::load: - {name} has bad key, store maybe corrupted')

    async def _append_store(self, k: NamedKeys):
        with open(self._file_name, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile, delimiter=',')
            kv = await self.get_store_key(k, self._encrypter)
            writer.writerow([
                k.name, kv
            ])


class SQLiteKeyStore(KeystoreInterface):
    """
        Keystore interface implemented using a sqlite use this
    """
    def __init__(self,
                 file_name: str,
                 encrypter: KeyDataEncrypter = None):
        self._file_name = file_name
        self._encrypter = encrypter
        self._db = None

    async def _init_store(self):
        if self._db is None:
            self._db = ASQLiteDatabase(self._file_name)
            await self._db.execute_sql(f'create table if not exists name_key_map('
                                       f'name text primary key not null,'
                                       f'key text)')

            rs = await self._db.select_sql(sql='select name,key from name_key_map limit 1')

            # this will force an encrypt action, which will stop us having a db ks encrpted with
            # different passwords
            if rs:
                await self._key_from_row(rs[0])

    async def _key_from_row(self, row) -> NamedKeys:
        ret = None

        name = row['name']
        key_str = row['key']

        # decrypt if required
        if self._encrypter is not None:
            key_str = await self._encrypter.decrypt_data(key_str)

        k = Keys.get_key(key_str)
        ret = NamedKeys(name=name,
                        priv_k=k.private_key_hex(),
                        pub_k=k.public_key_hex())
        return ret

    async def get(self, name: str) -> NamedKeys:
        ret = None
        # make sure store is loaded
        await self._init_store()

        rs = await self._db.select_sql(sql='select name,key  from name_key_map where name=?',
                                       args=[name])
        if rs:
            ret = await self._key_from_row(rs[0])

        return ret

    async def select(self, filter: list | dict = None) -> [NamedKeys]:
        # at the moment the filter is ignored and this just returns everything

        # make sure store is loaded
        await self._init_store()

        rs = await self._db.select_sql(sql='select name,key  from name_key_map')

        ret = [await self._key_from_row(c_row) for c_row in rs]

        return ret

    async def add(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        ret = self.named_keys(k, name)

        # make sure store is loaded
        await self._init_store()

        # try and add name, key to db will fail if it already exists
        try:
            await self._db.execute_sql(sql='insert into name_key_map values (?,?)',
                                       args=[ret.name,
                                             await self.get_store_key(ret, self._encrypter)])
        except Exception as e:
            raise KeyStoreException(f'FileKeyStore::add: {e}')

        return ret

    async def update(self, k: Keys | NamedKeys, name: str = None) -> NamedKeys:
        ret = self.named_keys(k, name)

        # make sure store is loaded
        await self._init_store()

        # try and add name, key in db will fail if it does not already exist
        try:
            # now do the update
            await self._db.execute_sql(sql='update name_key_map set key=? where name=?',
                                       args=[await self.get_store_key(ret, self._encrypter),
                                             ret.name])
        except Exception as e:
            raise KeyStoreException(f'SQLiteKeyStore::update: {e}')

        return ret

    async def delete(self, name: str = None) -> NamedKeys:
        ret = await self.get(name)
        if ret is None:
            raise KeyStoreException(f'SQLiteKeyStore::delete: {name} not found to delete')

        # try and add name, key in db will fail if it does not already exist
        try:
            # now do the update
            await self._db.execute_sql(sql='delete from name_key_map where name=?',
                                       args=[ret.name])
        except Exception as e:
            raise KeyStoreException(f'SQLiteKeyStore::delete: {e}')

        return ret

