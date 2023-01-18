import asyncio
import logging
from monstr.client.client import Client

async def basic_query_test():
    async with Client('ws://localhost:8888',
                      query_timeout=10) as c:
        events = await c.query({
            # 'authors': ['5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f']
        })
        for c_evt in events:
            print(c_evt)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(basic_query_test())