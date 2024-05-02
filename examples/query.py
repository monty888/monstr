import asyncio
import logging
import argparse
import sys
from pathlib import Path
from monstr.util import util_funcs
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event
from monstr.util import ConfigError
from monstr.encrypt import Keys
from monstr.ident.alias import ProfileFileAlias

# defaults
# working directory it'll be created it it doesn't exist
WORK_DIR = f'{Path.home()}/.nostrpy/'
#  relay to query
DEFAULT_RELAY = 'ws://localhost:8080'
# max time we'll wait for the query to complete
DEFAULT_TIMEOUT = 10
# limit on number of returned results
DEFAULT_LIMIT = 100
# kinds to return
DEFAULT_KINDS = None


def parse_filter(parse_args):
    # make sure kinds are all int if given
    if parse_args.kinds:
        q_kinds = []
        for c_kind in parse_args.kinds.split(','):
            try:
                q_kinds.append(int(c_kind))
            except ValueError as ve:
                raise ConfigError('kinds values must be integer, found %s' % c_kind)
                sys.exit(2)
        parse_args.kinds = q_kinds

    # if any author keys make sure they're ok and convert to key objects
    if parse_args.authors:
        # TODO: make this configurable
        alias_file = '%sprofiles.csv' % WORK_DIR
        # Note ProfileFileAlias won't error if it couldn't open the above file - it just logs the err
        # it just won't be able to map any of the aliases.
        my_alias = ProfileFileAlias(alias_file)
        author_keys = []
        for c_key in parse_args.authors.split(','):
            k = Keys.get_key(c_key)
            if k is not None:
                author_keys.append(k)
            else:
                p = my_alias.get_profile(c_key)
                if p:
                    author_keys.append(p.keys)
                else:
                    raise ConfigError('unable to create author keys from key value - %s' % c_key)
        parse_args.authors = author_keys

def get_args():
    parser = argparse.ArgumentParser(
        prog='query.py',
        description='simple program to send queries to nostr relays'
    )
    parser.add_argument('-r', '--relay', action='store', default=DEFAULT_RELAY,
                        help='comma separated urls of relays to connect to - default %s' % DEFAULT_RELAY)
    parser.add_argument('-t', '--timeout', action='store', type=int, default=DEFAULT_TIMEOUT,
                        help='max time to wait for query to complete - default %ss' % DEFAULT_TIMEOUT)
    parser.add_argument('-l', '--limit', action='store', type=int, default=DEFAULT_LIMIT,
                        help='limit number of returned events - default %s' % DEFAULT_LIMIT)
    parser.add_argument('-k', '--kinds', action='store', default=DEFAULT_KINDS,
                        help='comma separated kinds to query - default any')
    parser.add_argument('-a', '--authors', action='store', default=None,
                        help='comma separated list or author keys, can be nsec, npub, public hex or alias')
    parser.add_argument('-o', '--output', choices=['heads', 'full', 'raw'], default='full',
                        help='format to output events. heads - event_id@time, '
                             'full - includes event content, raw - the raw json str')
    parser.add_argument('--ssl_disable_verify', action='store_true', help='disables checks of ssl certificates')
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')

    ret = parser.parse_args()
    if ret.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # create our work dir if it doesn't exist... /HOME/.nostrpy/
    # currently not configurable
    util_funcs.create_work_dir(WORK_DIR)

    try:
        parse_filter(ret)
    except ConfigError as ce:
        print(ce)
        sys.exit()

    return ret


async def do_query(args):
    # is ssl cert checks disabled?
    ssl = None
    if args.ssl_disable_verify:
        ssl = False

    # make the query
    my_query = {
        'limit': args.limit
    }
    key_map = None

    if args.kinds:
        my_query['kinds'] = args.kinds
    if args.authors:
        c_k: Keys
        my_query['authors'] = [c_k.public_key_hex() for c_k in args.authors]
        key_map = {c_k.public_key_hex(): c_k for c_k in args.authors}

    async with ClientPool(args.relay.split(','),
                          query_timeout=args.timeout,
                          timeout=args.timeout,
                          ssl=ssl) as c:

        events = await c.query(my_query,
                               emulate_single=True,
                               wait_connect=True)

        Event.sort(events, inplace=True, reverse=False)

        c_evt: Event
        if not events:
            print('no events!')
        else:
            for c_evt in events:
                if args.output == 'raw':
                    print(c_evt.event_data())
                else:
                    if args.output in ('full', 'heads'):
                        print(c_evt)
                    if args.output == 'full':
                        # decrypt nip4, only from us currently. add to us and maybe add as simpler util method
                        # on Event?
                        if c_evt.kind == Event.KIND_ENCRYPT:
                            # dm to us
                            if key_map and c_evt.pub_key in key_map:
                                k: Keys = key_map[c_evt.pub_key]
                                if k.private_key_hex():
                                    to = None
                                    if c_evt.p_tags:
                                        for c_tag in c_evt.p_tags:
                                            to = c_tag
                                            if to != c_evt.pub_key:
                                                break

                                    if to:
                                        c_evt.content = c_evt.decrypted_content(k.private_key_hex(), to)

                        print(''.join(['-']*80))
                        for c_str in util_funcs.chunk(c_evt.content, 80):
                            print('> ' + c_str)
                        print()


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)
    asyncio.run(do_query(get_args()))
