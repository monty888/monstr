import logging
import asyncio
from monstr.client.client import Client, ClientPool

# default relay if not otherwise given
DEFAULT_RELAY = 'ws://localhost:8080'
FILTER = [{
    'limit': 100
}]


async def one_off_query_client_with(relay=DEFAULT_RELAY):
    # does a one off query to relay prints the events and exits
    async with Client(relay) as c:
        events = await c.query(FILTER)
        for c_evt in events:
            print(c_evt)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(one_off_query_client_with())
