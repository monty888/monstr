import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event


async def do_post(url, text):
    """
        Example showing how to post a text note (Kind 1) to relay
    """

    # rnd generate some keys
    n_keys = Keys()

    async with Client(url) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content=text,
                      pub_key=n_keys.public_key_hex())
        n_msg.sign(n_keys.private_key_hex())
        c.publish(n_msg)
        # await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    text = 'hello'

    asyncio.run(do_post(url, text))