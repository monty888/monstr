import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.event.persist_memory import RelayMemoryEventStore


async def run_relay():
    r = Relay(store=RelayMemoryEventStore())
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())