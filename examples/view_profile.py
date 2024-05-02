import sys
import logging
import signal
import asyncio
from cachetools import TTLCache
from aiohttp import web
from monstr.client.client import ClientPool, Client
from monstr.encrypt import Keys
from monstr.ident.event_handlers import NetworkedProfileEventHandler


class ServerError(Exception):
    pass


class MetaServer:

    def __init__(self,
                  client: Client):

        self._server = web.Application()
        self._runner = web.AppRunner(self._server)

        def test_route(request: web.Request):
            return web.Response(text='hi there')

        def _get_err_wrapped(method):
            async def _wrapped(*args, **kargs):
                try:
                    return await method(*args,**kargs)
                except ServerError as se:
                    return web.json_response({
                        'error': str(se)
                    })
            return _wrapped

        self._server.add_routes([
            web.get('/view_profile', _get_err_wrapped(self.view_profile_route))
        ])

        self._client = client
        self._my_peh = NetworkedProfileEventHandler(client=self._client,
                                                    cache=TTLCache(maxsize=1000,
                                                                   ttl=60*30))

    async def view_profile_route(self, request: web.Request):
        pub_k = ''
        if 'pub_k' in request.query:
            pub_k = request.query['pub_k']

        if pub_k == '':
            raise ServerError('pub_k param is required')

        k = Keys.get_key(pub_k)
        if k is None:
            raise ServerError(f'{pub_k} - doesn\'t look like a nonstr key')

        pub_k = k.public_key_hex()
        ret = {
            'pub_k': pub_k,
            'error': 'not found'
        }

        p = await self._my_peh.aget_profile(pub_k)
        if p:
            ret = p.as_dict()
        return web.json_response(ret)

    async def start(self, host='localhost', port=8081):
        logging.debug('started web server at %s port=%s' % (host, port))
        await self._runner.setup()
        site = web.TCPSite(self._runner,
                           host=host,
                           port=port)
        await site.start()

    def end(self):
        self._server.close()


async def start_server(relays):

    # exit cleanly on ctrl c
    run = True

    def sigint_handler(signal, frame):
        nonlocal run
        run = False

    signal.signal(signal.SIGINT, sigint_handler)

    # connection to relays
    # c = Client(relays[0])
    async with Client(relays[0]) as c:
        print('client started')
        meta_server = MetaServer(client=c)
        await meta_server.start()
        while run:
            await asyncio.sleep(0.1)

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    # relays = ['wss://nostr-pub.wellorder.net']
    relays= ['ws://localhost:8080']
    args = sys.argv[1:]
    if args:
        relays = args[0].split(',')

    asyncio.run(start_server(relays))
