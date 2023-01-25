import logging
import asyncio
from monstr.client.client import Client, ClientPool
from monstr.client.event_handlers import PrintEventHandler
from monstr.event.event import Event
from monstr.encrypt import Keys

# default relay if not otherwise given
DEFAULT_RELAY = 'ws://localhost:8888'


async def one_off_query_client_with(relay=DEFAULT_RELAY):
    """
    doing a basic query using with to manage context
    :param relay:
    :return:
    """
    async with Client(relay) as c:
        events = await c.query({
            'limit': 100
        })

        for c_evt in events:
            print(c_evt)


async def one_off_query_manual(relay=DEFAULT_RELAY):
    """
    doing a one off query managing the client manually
    :param relay:
    :return:
    """
    c = ClientPool(DEFAULT_RELAY)
    asyncio.create_task(c.run())
    await c.wait_connect()
    events = await c.query({
        'limit': 100
    })

    for c_evt in events:
        print(c_evt)
    c.end()


async def simple_sub(relay=DEFAULT_RELAY):
    my_handler = PrintEventHandler()

    async with Client(relay) as c:
        c.subscribe(handlers=my_handler,
                    filters={
                        'kinds': Event.KIND_TEXT_NOTE
                    })

        # wait 10 secs for some events to come in
        await asyncio.sleep(10)


async def make_post(relay=DEFAULT_RELAY):
    n_keys = Keys()
    async with Client(relay) as c:
        n_msg = Event(kind=Event.KIND_TEXT_NOTE,
                      content='hello there!',
                      pub_key=n_keys.public_key_hex())
        n_msg.sign(n_keys.private_key_hex())
        # send it once
        c.publish(n_msg)
        # this 2nd time sign with another key so we should recieve an OK command err
        n_msg.sign(Keys().private_key_hex())
        c.publish(n_msg)
        await asyncio.sleep(1)

async def main():
    await one_off_query_client_with()
    await one_off_query_manual()
    await simple_sub()
    await make_post()

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(main())
