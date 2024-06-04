import asyncio
import logging
from hashlib import sha256
from monstr.ident.keystore import NamedKeys, FileKeyStore, KeyDataEncrypter, SQLiteKeyStore
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.profile import Profile

# logging.getLogger().setLevel(logging.DEBUG)


async def convert_store():
    # load the old data as alias stores it
    old_file = '/home/monty/.nostrpy/profiles.csv'

    # create a new key store and copy name/key maps in
    new_file = '/home/monty/.nostrpy/keystore.db'


    async def get_key() -> str:
        # will block, use aiconsole where it matters
        return input('keystore key: ')

    my_enc = KeyDataEncrypter(get_key=get_key)
    new_store = SQLiteKeyStore(new_file,
                               encrypter=my_enc)

    await new_store.convert_memstore(old_file)



async def test_store():
    # create a new key store and copy name/key maps in
    new_file = '/home/monty/.nostrpy/keystore.db'
    async def get_key() -> str:
        # will block, use aiconsole where it matters
        return input('keystore key: ')

    my_enc = KeyDataEncrypter(get_key=get_key)

    new_store = SQLiteKeyStore(new_file,
                             encrypter=my_enc)

    await new_store.add(NamedKeys('moobs'))

    # print(await new_store.get('monty_test'))
    #
    # from monstr.encrypt import Keys
    # await new_store.update(Keys(), 'monty_test')

asyncio.run(convert_store())



# nk = NamedKeys('shaun')
#
# print(nk)
#
# my_store = FileKeyStore('/home/monty/.nostrpy/profiles.csv')
# print(my_store.get('che'))
#
# k = NamedKeys(name='c')
# my_store.update(k)