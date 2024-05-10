import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.relay.accept_handlers import RestrictDM
from monstr.encrypt import Keys

ACCEPT_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')


async def run_relay():
    """
        authentication used to restrict what events subscriptions return
    """
    print(f'should only return kind 4 encryped and kind 1059 gift wrapped if the auth user should see them...')
    r = Relay(request_auth=True, sub_filter=RestrictDM())
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())