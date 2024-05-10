import asyncio
import logging
from monstr.relay.relay import Relay
from monstr.relay.accept_handlers import AuthenticatedAcceptor, POWAcceptor, ORAcceptor
from monstr.encrypt import Keys

ACCEPT_KEY = Keys('nsec14wraxv90yphe9pkh0p84xh99h4ean86lk56lejf35886yjnvmpkqzqfwvy')

async def run_relay():

    # accept only post from this key, anyone else we'll need do add min power of 16
    # if we did authorised_keys=[] then anyone could post but only if they'd authed
    # my_acceptor = AuthenticatedAcceptor(authorised_keys=[ACCEPT_KEY.public_key_hex()],
    #                                     descriptive_msg='some message cause you gay!!!')
    min_pow = 16
    my_acceptor = ORAcceptor([POWAcceptor(min_pow),
                              AuthenticatedAcceptor(ACCEPT_KEY.public_key_hex())])

    print(f'accepting posts from {ACCEPT_KEY.private_key_bech32()} only! else event will need pow of atleast {min_pow}')
    r = Relay(request_auth=True,accept_req_handler=[my_acceptor])
    await r.start()

if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    asyncio.run(run_relay())