import asyncio
import logging
import argparse
import sys
from monstr.util import util_funcs
from monstr.client.client import Client, ClientPool
from monstr.event.event import Event

# defaults
#  relay to query
DEFAULT_RELAY = 'ws://localhost:8888'
# max time we'll wait for the query to complete
DEFAULT_TIMEOUT = 10
# limit on number of returned results
DEFAULT_LIMIT = 100
# kinds to return
DEFAULT_KINDS = None


def get_args():
    parser = argparse.ArgumentParser(
        prog='NostrQuery',
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
    parser.add_argument('-d', '--debug', action='store_true', help='enable debug output')
    parser.add_argument('-o', '--output', choices=['heads', 'full', 'raw'], default='full',
                        help='format to output events. heads - event_id@time, '
                             'full - includes event content, raw - the raw json str')

    ret = parser.parse_args()
    if ret.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # make sure kinds are all int if given
    if ret.kinds:
        q_kinds = []
        for c_kind in ret.kinds:
            try:
                q_kinds.append(int(c_kind))
            except ValueError as ve:
                print('kinds values must be integer, found %s' % c_kind)
                sys.exit(2)
        ret.kinds = q_kinds

    return ret


async def do_query(args):
    async with Client(args.relay,
                      query_timeout=args.timeout) as c:

        my_query = {
            'limit': args.limit
        }

        if args.kinds:
            my_query['kinds'] = args.kinds

        events = await c.query(my_query)
        Event.sort(events, inplace=True, reverse=False)


        c_evt: Event
        for c_evt in events:
            if args.output == 'raw':
                print(c_evt.event_data())
            else:
                if args.output in ('full', 'heads'):
                    print(c_evt)
                if args.output == 'full':
                    print(''.join(['-']*80))
                    for c_str in util_funcs.chunk(c_evt.content, 80):
                        print('> ' + c_str)
                    print()

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.ERROR)

    asyncio.run(do_query(get_args()))
