import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.signing import BasicKeySigner


async def do_post(url, text, target):
    """
        Example showing how to post a text note (Kind 1) to relay with a minimum level of pow
    """

    # create signer with rnd generate some keys - different signers will have diff constructors
    my_signer = BasicKeySigner(key=Keys())

    async with Client(url) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      pub_key=await my_signer.get_public_key(),
                      content=text)
        n_msg.add_pow(target=target)
        n_msg = await my_signer.ready_post(n_msg)

        c.publish(n_msg)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    target = 12
    text = f'hello this event should have a pow of {target} bits'

    asyncio.run(do_post(url, text, target))