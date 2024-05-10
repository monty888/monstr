"""
    post text type note from the command line either supply a private key or a random key will created
"""
import sys
import signal
import logging
import asyncio
import aioconsole
import argparse
from monstr.encrypt import Keys
from monstr.client.client import ClientPool, Client
from monstr.event.event import Event
from monstr.util import ConfigError

# default relay
RELAY = 'ws://localhost:8080'
# default from user
FROM_USER = None
# default to user
TO_USER = None


def get_args():
    ret = get_cmdline_args({
        'relay': RELAY,
        'as_user': FROM_USER,
        'to_user': TO_USER
    })

    if ret.debug:
        logging.getLogger().setLevel(logging.ERROR)

    if ret.as_user is None:
        ret.as_user = Keys()
        print(f'created new key for posting - {ret.as_user.public_key_bech32()}')
    else:
        if not Keys.is_bech32_key(ret.as_user):
            raise ConfigError(f'{ret.as_user} doesn\'t look like a valid nostr key, only npub/nsec accepted')
        if ret.as_user.startswith('npub'):
            raise ConfigError('a private key is required for posting')
        ret.as_user = Keys(ret.as_user)
        print(f'using existing key for posting - {ret.as_user.public_key_bech32()}')

    if ret.to_user:
        if not Keys.is_valid_key(ret.to_user):
            raise ConfigError(f'{ret.to_user} doesn\'t look like a valid nostr key')
        ret.to_user = Keys.get_key(ret.to_user)
        print(f'posting to - {ret.to_user.public_key_bech32()}')
    else:
        print(f'posting to everyone')

    return ret


def get_cmdline_args(args) -> dict:
    parser = argparse.ArgumentParser(
        prog='post_text.py',
        description="""
            post text notes
            """
    )
    parser.add_argument('-r', '--relay', action='store', default=args['relay'],
                        help=f'comma separated nostr relays to connect to, default[{args["relay"]}]')
    parser.add_argument('-a', '--as_user', action='store', default=args['as_user'],
                        help=f"""
                        priv_k of user to post as,
                        default[{args['as_user']}]""")
    parser.add_argument('-t', '--to_user', action='store', default=args['as_user'],
                        help=f"""
                        nostr key of user to post to,
                        default[{args['to_user']}]""")
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    ret = parser.parse_args()

    return ret


async def prompt_post(args):
    """
    loops around accepting text and then posting that to the relay until user types exit
    :param priv_k:
    :param relay:
    :return:
    """

    relay = args.relay.split(',')
    as_user: Keys = args.as_user
    to_user: Keys = args.to_user

    print('type exit to quit')
    msg_n = ''

    def on_auth(the_client: Client, challenge: str):
        asyncio.create_task(the_client.auth(as_user, challenge))

    client = ClientPool(clients=relay,
                        on_auth=on_auth)

    asyncio.create_task(client.run())


    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        print('stopping...')
        client.end()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    while msg_n != 'exit':
        msg = await aioconsole.ainput('> ')
        msg_n = msg.lower().replace(' ', '')
        if msg_n != '' and msg_n != 'exit':
            tags = []
            if to_user:
                tags = [['p', to_user.public_key_hex()]]

            n_event = Event(kind=Event.KIND_TEXT_NOTE,
                            content=msg,
                            pub_key=as_user.public_key_hex(),
                            tags=tags)
            n_event.sign(as_user.private_key_hex())
            client.publish(n_event)

    print('stopping...')
    client.end()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    try:
        print(asyncio.run(prompt_post(get_args())))
    except ConfigError as ce:
        print(ce)

