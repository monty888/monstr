import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.encrypt import NIP44Encrypt

async def do_post(url, text, to_k):
    """
        Example showing how to post a encrypted note (Kind 4) to relay
    """
    # rnd generate some keys we sending as
    n_keys = Keys()
    my_enc = NIP44Encrypt(n_keys)

    async with Client(url) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content=text,
                      pub_key=n_keys.public_key_hex())

        # returns event we to_p_tag and content encrypted
        n_msg = my_enc.encrypt_event(evt=n_msg,
                                     to_pub_k=to_k)

        n_msg.sign(n_keys.private_key_hex())
        c.publish(n_msg)
        # await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    to_k = Keys('nsec1znc5uy6e342rzn420l38q892qzmkvjz0hn836hhn8hl8wmkc670qp0lk9n')
    text = f'hello this is nip4 encrypted to {to_k.public_key_hex()}'

    asyncio.run(do_post(url, text, to_k))