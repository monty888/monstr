import asyncio
import logging
from monstr.client.client import Client
import signal
from monstr.event.event import Event
from monstr.util import util_funcs
from monstr.encrypt import Keys

ACCEPT_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')
tail = util_funcs.str_tails


async def listen_notes(url):
    """
        as note_listen.py except we auth as ACCEPT_KEY
        which means that when running with run_relay_auth_sub.py
        we should see kind 4 dms and .....
    """
    run = True

    # so we get a clean exit on ctrl-c
    def sigint_handler(signal, frame):
        nonlocal run
        run = False
    signal.signal(signal.SIGINT, sigint_handler)

    # just use func, you can also use a class that has a do_event
    # with this method sig, e.g. extend monstr.client.EventHandler
    def my_handler(the_client: Client, sub_id: str, evt: Event):
        print(evt.created_at, tail(evt.id), tail(evt.content, 30))

    def on_connect(the_client: Client):
        # sub in onconnect so will re-sub if disconnect
        the_client.subscribe(handlers=my_handler,
                             filters={
                                 'limit': 100
                             })

    def on_auth(the_client: Client, challenge: str):
        asyncio.create_task(the_client.auth(ACCEPT_KEY, challenge))

    # create the client and start it running
    c = Client(url,
               on_connect=on_connect,
               on_auth=on_auth)
    asyncio.create_task(c.run())
    await c.wait_connect()

    while run:
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    url = "ws://localhost:8080"

    asyncio.run(listen_notes(url))