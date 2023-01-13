"""
    post text type note from the command line either supply a private key or a random key will created
"""
import sys
import signal
import logging
from monstr.encrypt import Keys
from monstr.client.client import Client
from monstr.event.event import Event


def prompt_post(keys:Keys, relay='ws://localhost:8888'):
    """
    loops around accepting text and then posting that to the relay until user types exit
    :param priv_k:
    :param relay:
    :return:
    """
    print('making posts for pub_k - %s' % keys.public_key_hex())
    print('type exit to quit')
    msg_n = ''

    client = Client(relay_url=relay)
    client.start()

    # exit cleanly on ctrl c
    def sigint_handler(signal, frame):
        print('stopping...')
        client.end()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    while msg_n != 'exit':
        msg = input('> ')
        msg_n = msg.lower().replace(' ', '')
        if msg_n != '' and msg_n != 'exit':
            n_event = Event(kind=Event.KIND_TEXT_NOTE,
                            content=msg,
                            pub_key=keys.public_key_hex())
            n_event.sign(keys.private_key_hex())
            client.publish(n_event)

    print('stopping...')
    client.end()



if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    args = sys.argv[1:]

    if not args:
        my_keys = Keys()
        print('created new key for posting')
    else:
        for_key = args[0]
        if not Keys.is_bech32_key(for_key):
            print('%s doesn\'t look like a valid monstr key, only npub/nsec accepted' % for_key)
            sys.exit(2)
        if for_key.startswith('npub'):
            print('a private key is required for posting')
            sys.exit(2)
        my_keys = Keys.get_key(for_key)

    prompt_post(my_keys)