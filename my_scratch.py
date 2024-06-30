import asyncio
import logging
from getpass import getpass
from hashlib import sha256
from monstr.ident.keystore import NamedKeys, FileKeyStore, NIP44KeyDataEncrypter, NIP49KeyDataEncrypter, SQLiteKeyStore
from monstr.ident.persist import MemoryProfileStore
from monstr.ident.profile import Profile
from monstr.encrypt import Keys

logging.getLogger().setLevel(logging.DEBUG)


async def get_key() -> str:
    # will block, use aiconsole where it matters
    return getpass('keystore key: ')


async def convert_store():
    # load the old data as alias stores it
    old_file = '/home/monty/.nostrpy/profiles.csv'

    # create a new key store and copy name/key maps in
    new_file = '/home/monty/.nostrpy/keystore2.db'

    my_enc = NIP44KeyDataEncrypter(get_password=get_key)
    new_store = FileKeyStore(new_file,
                             encrypter=my_enc)

    await new_store.convert_memstore(old_file)


async def test_store():
    # create a new key store and copy name/key maps in
    new_file = '/home/monty/.nostrpy/keystore2.db'

    my_enc = NIP44KeyDataEncrypter(get_password=get_key)

    new_store = SQLiteKeyStore(file_name=new_file,
                               encrypter=my_enc)

    # await new_store.add(NamedKeys('moobs'))
    await new_store.delete('monty')
    for c_k in await new_store.select():
        print(c_k)

    # print(await new_store.get('monty_test'))
    #
    # from monstr.encrypt import Keys
    # await new_store.update(Keys(), 'monty_test')

async def convert_store():
    old_store = SQLiteKeyStore(file_name='/home/monty/.nostrpy/keystore.db',
                               encrypter=NIP44KeyDataEncrypter(password=''))
    new_store = SQLiteKeyStore(file_name='/home/monty/.nostrpy/keystore2.db',
                               encrypter=NIP49KeyDataEncrypter(password=''))
    await SQLiteKeyStore.merge_key_store(old_store, new_store)

# Example usage
if __name__ == "__main__":
    # password = "nostr"
    # private_key_hex = Keys.get_key("3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683",hex_default='private')
    # print(private_key_hex.public_key_hex())
    # pub_k_only = Keys.get_key(private_key_hex.public_key_bech32())
    #
    # log_n = 16
    # key_security_byte = 0x01
    #
    #
    # encrypted_key = NIP49.encrypt_key(password, pub_k_only, log_n, key_security_byte,support_pub_k=True)
    # print(f"Encrypted Private Key: {encrypted_key}")
    #
    # decrypted_key = NIP49.decrypt_key(password, encrypted_key, support_pub_k=True)
    # print(f"Decrypted Private Key: {decrypted_key}")
    #
    # encrypted_key = 'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p'
    # decrypted_key = NIP49.decrypt_key(password, encrypted_key)
    # print(f"Decrypted Private Key: {decrypted_key}")

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