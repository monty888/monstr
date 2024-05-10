import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.encrypt import NIP4Encrypt

USE_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')

async def do_post(url, text, to_k):
    """
        Example showing how to post a encrypted note (Kind 4) to relay
    """

    my_enc = NIP4Encrypt(USE_KEY)

    async with Client(url) as c:
        n_msg = Event(kind=Event.KIND_ENCRYPT,
                      content=text,
                      pub_key=USE_KEY.public_key_hex())

        # returns event we to_p_tag and content encrypted
        n_msg = my_enc.encrypt_event(evt=n_msg,
                                     to_pub_k=to_k)

        n_msg.sign(USE_KEY.private_key_hex())
        c.publish(n_msg)

        # await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    to_k = Keys('nsec1znc5uy6e342rzn420l38q892qzmkvjz0hn836hhn8hl8wmkc670qp0lk9n')
    text = f'hello this is nip4 encrypted to {to_k.public_key_hex()}'

    asyncio.run(do_post(url, text, to_k))