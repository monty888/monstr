import asyncio
import logging
from monstr.encrypt import Keys
from monstr.signing.nip46 import NIP46ServerConnection
from monstr.signing.signing import BasicKeySigner

# url to relay used for talking to the signer
RELAY = 'ws://localhost:8080'


async def run_signer():
    """
        Run a service that'll sign events via NIP46 for some random keys
    """
    # rnd generate some keys
    n_keys = Keys()

    # create the signing service
    my_signer = NIP46ServerConnection(signer=BasicKeySigner(n_keys),
                                      relay=RELAY)

    # output info needed for client to connect to the signer
    print(await my_signer.bunker_url)

    # wait forever...
    while True:
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_signer())
