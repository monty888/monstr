import asyncio
import logging
from monstr.relay.relay import Relay
"""
    runs a relay - this won't be storing any events so all queries to it'll will return empty
"""
async def run_relay():
    r = Relay()
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())