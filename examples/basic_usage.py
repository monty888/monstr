import logging
import asyncio
from monstr.client.client import Client

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
    c = Client(DEFAULT_RELAY)
    asyncio.create_task(c.run())
    await c.wait_connect()
    events = await c.query({
        'limit': 100
    })

    for c_evt in events:
        print(c_evt)
    c.end()


async def main():
    # await one_off_query_client_with()
    await one_off_query_manual()

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(main())