import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.relay.accept_handlers import AuthenticatedAcceptor, POWAcceptor, ORAcceptor
from monstr.encrypt import Keys

ACCEPT_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')


async def run_relay():
    min_pow = 16
    my_acceptor = ORAcceptor([POWAcceptor(min_pow),
                              AuthenticatedAcceptor(ACCEPT_KEY.public_key_hex())])

    print(f'accepting posts from {ACCEPT_KEY.private_key_bech32()} only! else event will need pow of at least {min_pow}')
    r = Relay(request_auth=True, accept_req_handler=[my_acceptor])
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())