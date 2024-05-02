import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.signing import BasicKeySigner

async def do_post(url, text):
    """
        Example showing how to post a text note (Kind 1) to relay
        using signer class - better way to do things than using the evt.sign method as it allows the
        signing/decryption to be extracted awat (we don't necessarily need to have access to the keys ourself)
        though we do here with the BasicKeySigner
    """

    # create signer with rnd generate some keys - different signers will have diff constructors
    my_signer = BasicKeySigner(key=Keys())

    async with Client(url) as c:
        n_msg = await my_signer.ready_post(Event(kind=Event.KIND_TEXT_NOTE,
                                                 content=text))
        await my_signer.sign_event(n_msg)
        c.publish(n_msg)
        # await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    text = 'hello using signer'

    asyncio.run(do_post(url, text))