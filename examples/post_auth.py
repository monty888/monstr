import asyncio
import logging
from monstr.client.client import Client, ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event

# only user that run_relay_auth.py is set to accept
ACCEPT_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')


async def do_post(url, text):
    """
        Example showing how to post a text note (Kind 1) to relay
        where we authenticate before posting
        to use with run_relay_auth.py
    """

    is_auth = False

    def on_auth(the_client: Client, challenge: str):
        nonlocal is_auth
        asyncio.create_task(the_client.auth(ACCEPT_KEY, challenge))
        is_auth = True

    async def wait_auth(max_wait=2):
        waited = 0.0
        while is_auth is False and waited < float(max_wait):
            await asyncio.sleep(0.1)

    async with Client(url, on_auth=on_auth) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content=text,
                      pub_key=ACCEPT_KEY.public_key_hex())

        # adding this line should allow posts even without auth
        # n_msg.add_pow(16)
        n_msg.sign(ACCEPT_KEY.private_key_hex())

        # wait for auth to happen, note if a relay doesn't expect authentication then it'd never happen
        # so we have a timeout. Also if you lose connection you'd probably need to reauth
        await wait_auth()
        # we attempt to publish we don't even check if we actually authed...
        c.publish(n_msg)
        await asyncio.sleep(1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"
    text = 'hello'

    asyncio.run(do_post(url, text))