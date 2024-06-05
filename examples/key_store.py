"""
    example showing the use of an encrypted keystore
    here keys are kept mapped to a local alias

"""
import sys
import os
import asyncio
import logging
from pathlib import Path
from monstr.ident.keystore import SQLiteKeyStore, KeystoreInterface, KeyDataEncrypter, NamedKeys
from monstr.util import util_funcs

# db will be stored here
WORK_DIR = f'{Path.home()}/.nostrpy/'
# key store base
DB_FILE = 'key_store_example.db'


async def get_key() -> str:
    # get password to unlock keystore
    return input('keystore key: ')


async def get_store() -> KeystoreInterface:
    # keys encrypted with pw, if encryptor not sent in then keys are store in plain_text
    my_enc = KeyDataEncrypter(get_key=get_key)

    return SQLiteKeyStore(WORK_DIR + DB_FILE,
                          encrypter=my_enc)


async def add(name: str):
    store = await get_store()
    nk = await store.add(NamedKeys(name=name))
    print(f'new key map added {name}')
    print(nk)


async def get(name: str):
    store = await get_store()
    nk = await store.get(name)
    if nk:
        print(f'found {name}')
        print(nk)
    else:
        print(f'{name} does\'t exist in the store')


def delete():
    # delete the db file all key maps will be lost
    os.remove(WORK_DIR + DB_FILE)


def usage():
    print("""usage:
            # looks for key in the store and prints out key info
            python key_store.py [name]

            # add name with a newly generated key
            python key_store.py add [name]

            # deletes the store
            python key_store.py delete
            """)


if __name__ == "__main__":
    # logging.getLogger().setLevel(logging.DEBUG)
    # create work dir if it doesn't exist
    util_funcs.create_work_dir(WORK_DIR)
    args = sys.argv[1:]
    if not args:
        usage()
    else:
        if len(args) == 1:
            if args[0].lower() == 'delete':
                delete()
            else:
                asyncio.run(get(args[0]))
        elif len(args) == 2 and args[0].lower() == 'add':
            asyncio.run(add(args[1]))
        else:
            usage()
