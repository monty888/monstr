from abc import ABC, abstractmethod
import logging
import asyncio
import json
from json import JSONDecodeError
from urllib.parse import urlparse, parse_qs
from monstr.client.client import ClientPool, Client
from monstr.encrypt import Keys
from monstr.event.event import Event
from monstr.client.event_handlers import EventHandler, DeduplicateAcceptor
from monstr.signing.signing import SignerInterface, BasicKeySigner
from monstr.util import util_funcs


class SignerException(Exception):
    pass


class NIP46AuthoriseInterface(ABC):
    @abstractmethod
    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        pass


class NIP46ServerConnection(EventHandler):
    """
        this is the server side of a NIP46 signing process.
        It'll listens and signs events on behalf of a client that requests it so that the
        client never holds the keys itself.
    """
    def __init__(self,
                 signer: SignerInterface,
                 relay: [str],
                 comm_k: str = None,
                 authoriser: NIP46AuthoriseInterface = None):

        self._signer = signer
        self._comm_k = comm_k

        self._relay = relay
        if isinstance(relay, str):
            self._relay = [relay]

        self._authoriser = authoriser

        # TODO - make client so that if it gets async for _on_connect, _do_event
        # it'll automaticlly create as task
        def _on_connect(my_client: Client):
            asyncio.create_task(_aon_connect(my_client))

        async def _aon_connect(my_client:Client):
            my_client.subscribe(
                handlers=[self],
                filters={
                    '#p': [await self._signer.get_public_key()],
                    'kinds': [Event.KIND_NIP46]
                }
            )

        self._run = True
        self._client = ClientPool(self._relay,
                                  on_connect=_on_connect)

        # events queued and dealt with serially as they come in
        self._event_q: asyncio.Queue = asyncio.Queue()
        # start a process to work on the queued events
        self._event_process_task = asyncio.create_task(self._my_event_consumer())

        # TODO: we should probably have start and end, etc as client
        #  not just start a task here...
        asyncio.create_task(self._client.run())

        super().__init__(event_acceptors=[
            DeduplicateAcceptor()
        ])

    @property
    async def bunker_url(self):
        return f'bunker://{await self._signer.get_public_key()}?relay={"&".join(self._relay)}'

    async def describe(self):
        # await self._client.wait_connect()
        sign_k = await self._signer.get_public_key()

        content = json.dumps({
            'id': 'somerndstring',
            'result': ['describe',
                       'get_public_key',
                       'sign_event',
                       'nip04_encrypt',
                       'nip04_decrypt',
                       'connect'],
            'error': None
        })

        content = await self._signer.nip4_encrypt(content, to_pub_k=self._comm_k)

        con_event = Event(pub_key=sign_k,
                          kind=Event.KIND_NIP46,
                          content=content,
                          tags=[
                              ['p', self._comm_k]
                          ]
                          )

        await self._signer.sign_event(con_event)

        self._client.publish(con_event)

    async def _get_msg_event(self, content: str) -> Event:
        # returns encrypted and signed method for content

        # encrypt the content
        content = await self._signer.nip4_encrypt(content,
                                                  to_pub_k=self._comm_k)
        # make the event
        ret = Event(pub_key=await self._signer.get_public_key(),
                    kind=Event.KIND_NIP46,
                    content=content,
                    tags=[
                        ['p', self._comm_k]
                    ]
                )
        # and sign it
        await self._signer.sign_event(ret)

        return ret

    async def _do_response(self, result: str = None, error: str = None, id: str = None):
        if result is None:
            result = ''
        if error is None:
            error = ''
        if id is None:
            id = util_funcs.get_rnd_hex_str(8)

        evt = await self._get_msg_event(json.dumps({
            'id': id,
            'result': result,
            'error': error
        }))

        self._client.publish(evt)

    async def _do_command(self, method: str, params: [str]):
        id = util_funcs.get_rnd_hex_str(8)

        evt = await self._get_msg_event(json.dumps({
            'id': id,
            'method': method,
            'params': params
        }))

        self._client.publish(evt)
        return id

    async def request_connect(self):
        await self._do_command('connect', [await self._signer.get_public_key()])

    async def connect(self, id: str, params: [str]):
        if self._comm_k is None:
            self._comm_k = params[0]

        await self._do_response(result=await self._signer.get_public_key(),
                                id=id)

    async def get_public_key(self, id: str, params: [str]):
        await self._do_response(result=await self._signer.get_public_key(),
                                id=id)

    async def nip04_encrypt(self, id: str, params: [str]):
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::nip04_encrypt: requires 2 params got {n_params} - from key and ciper text')

            to_k = params[0]
            plain_text = params[1]
            if not Keys.is_hex_key(to_k):
                raise SignerException(
                    f'Signer::nip04_encrypt: from key is not valid {to_k}')

            ciper_text = await self._signer.nip4_encrypt(plain_text=plain_text,
                                                         to_pub_k=to_k)

            await self._do_response(result=ciper_text,
                                    id=id)

        except SignerException as se:
            await self._do_response(error=str(se),
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::nip04_encrypt:'
                                          f'unable to decrypt as {await self._signer.get_public_key()}'
                                          f' error - {str(e)}',
                                    id=id)

    async def nip04_decrypt(self, id: str, params: [str]):
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::nip04_decrypt: requires 2 params got {n_params} - from key and ciper text')

            from_k = params[0]
            payload = params[1]
            if not Keys.is_hex_key(from_k):
                raise SignerException(
                    f'Signer::nip04_decrypt: from key is not valid {from_k}')

            plain_text = await self._signer.nip4_decrypt(payload=payload,
                                                   for_pub_k=from_k)

            await self._do_response(result=plain_text,
                                    id=id)

        except SignerException as se:
            await self._do_response(error=str(se),
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::nip04_decrypt:'
                                          f'unable to decrypt as {await self._signer.get_public_key()}'
                                          f' error - {str(e)}',
                                    id=id)

    async def sign_event(self, id: str, params: [str]):
        try:
            evt_data = json.loads(params[0])
            event = Event.load(evt_data)

            await self._signer.sign_event(event)
            await self._do_response(result=json.dumps(event.data()),
                                    id=id)

        except JSONDecodeError as je:
            await self._do_response(error=f'Signer::sign_event: bad event JSON - {je}',
                                    id=id)
        except Exception as e:
            await self._do_response(error=f'Signer::sign_event: {e}',
                                    id=id)

    async def _my_event_consumer(self):
        while self._run:
            try:
                args = await self._event_q.get()
                await self.ado_event(*args)

            except Exception as e:
                logging.debug(f'NIP46ServerConnection::_my_event_consumer: {e}')

    def do_event(self, the_client: Client, sub_id, evt: Event):
        if not self.accept_event(the_client=the_client,
                                 sub_id=sub_id,
                                 evt=evt):
            return
        # put events on a queue so we can deal with async
        self._event_q.put_nowait(
            (the_client, sub_id, evt)
        )

    async def ado_event(self, the_client: Client, sub_id, evt: Event):
        decrypted_evt = await self._signer.nip4_decrypt_event(evt)

        try:
            cmd_dict = json.loads(decrypted_evt.content)
            if 'method' in cmd_dict:
                id = cmd_dict['id']
                method = cmd_dict['method']
                params = cmd_dict['params']

                if method in {'connect',
                              'describe',
                              'get_public_key',
                              'nip04_decrypt',
                              'nip04_encrypt',
                              'sign_event'}:
                    logging.info(f'{method} - {params}')

                    if self._authoriser:
                        if await self._authoriser.authorise(method, id, params):
                            await getattr(self, method)(id, params)
                        else:
                            await self._do_response(error='request not authorised!',
                                                    id=id)
                    else:
                        await getattr(self, method)(id, params)

        except Exception as e:
            logging.debug(f'SignerConnection::ado_event {e}')

    def end(self):
        self._run = False
        self._client.end()


class NIP46Comm(EventHandler):

    def __init__(self,
                 client: str | Client | list[str | Client],
                 for_k: str,
                 signer: SignerInterface):

        self._signer = signer
        self._comm_k = None
        self._for_k = for_k

        # events queued and dealt with serially as they come in
        self._event_q: asyncio.Queue = asyncio.Queue()
        # start a process to work on the queued events
        self._event_process_task = asyncio.create_task(self._my_event_consumer())

        self._client = ClientPool(client)
        asyncio.create_task(self._client.run())
        self._run = False

        super().__init__(event_acceptors=[
            DeduplicateAcceptor()
        ])

    async def connect(self, timeout=5) -> bool:
        if self._comm_k is None:
            await self.do_command(method='connect',
                                  params=[await self._signer.get_public_key()])

        return self._comm_k is not None

    async def _get_msg_event(self, content: str, to_k: str) -> Event:
        # encrypt the content
        content = await self._signer.nip4_encrypt(content,
                                                  to_pub_k=to_k)
        # make the event
        ret = Event(pub_key=await self._signer.get_public_key(),
                    kind=Event.KIND_NIP46,
                    content=content,
                    tags=[
                        ['p', to_k]
                    ]
                )
        # and sign it
        await self._signer.sign_event(ret)

        return ret

    async def do_command(self, method: str, params: [str]):
        id = util_funcs.get_rnd_hex_str(8)

        if method == 'connect':
            to_k = self._for_k
        else:
            to_k = self._comm_k
        if to_k is not None:
            evt = await self._get_msg_event(
                content=json.dumps({
                        'id': id,
                        'method': method,
                        'params': params
                    }),
                to_k=to_k
            )

            self._client.publish(evt)
        else:
            print('something went wrong... maybe we did not connect yet')

        return id

    def do_event(self, the_client: Client, sub_id, evt: Event):
        pass

    async def ado_event(self, the_client: Client, sub_id, evt: Event):
        pass

    async def _my_event_consumer(self):
        while self._run:
            try:
                args = await self._event_q.get()
                await self.ado_event(*args)

            except Exception as e:
                logging.debug(f'NIP46Comm::_my_event_consumer: {e}')

    def start(self):
        asyncio.create_task(self._client.run())

    def end(self):
        self._run = False
        self._client.end()

class NIP46Signer(SignerInterface):
    """
        signer that proxies signing via NIP46 - it never has access to the keys itself

        for now expects connection str, todo add where we initialise the connection
    """
    def __init__(self, connection: str):
        parsed = urlparse(connection)

        if parsed.scheme != 'bunker':
            raise SignerException(f'NIP46Signer::__init__: unknown connection scheme {parsed.scheme}')

        # keys we'll be signing as
        for_pub_k = parsed.netloc
        if not Keys.is_valid_key(for_pub_k):
            raise SignerException(f'NIP46Signer::__init__: bad key {for_pub_k}')
        self._for_pub_k = for_pub_k

        query_parsed = parse_qs(parsed.query)
        if 'relay' not in query_parsed:
            raise SignerException(f'NIP46Signer::__init__: relay not supplied')

        # probably we should do more checks on the relay urls....
        self._relay = query_parsed['relay']

        # does the comm between us and the NIP46 server, we use ephemeral keys for signing
        self._comm = NIP46Comm(client=self._relay,
                               for_k=for_pub_k,
                               signer=BasicKeySigner(Keys()))

    async def _get_comm_key(self):
        await self._comm.do_command(method='connect',
                                    params=[])

    async def _do_method(self, method: str, args: list) -> Event:
        logging.debug(f'NIP46Signer::_do_method: {method} - {args}')
        # did we already get key to connect on?
        await self._comm.connect()

    async def get_public_key(self) -> str:
        # we know the pub k so won't bother calling signer service for this
        return self._for_pub_k

    async def sign_event(self, evt: Event):
        await self._do_method('sign_event', [json.dumps(evt.data())])

    async def echd_key(self, to_pub_k: str) -> str:
        pass

    async def nip4_encrypt(self, plain_text: str, to_pub_k: str) -> str:
        pass

    async def nip4_decrypt(self, payload: str, for_pub_k: str) -> str:
        pass

    async def nip4_encrypt_event(self, evt: Event, to_pub_k: str) -> Event:
        pass

    async def nip4_decrypt_event(self, evt: Event) -> Event:
        pass

    async def nip44_encrypt(self, plain_text: str, to_pub_k: str, version=2) -> str:
        pass

    async def nip44_decrypt(self, payload: str, for_pub_k: str) -> str:
        pass

    async def nip44_encrypt_event(self, evt: Event, to_pub_k: str) -> Event:
        pass

    async def nip44_decrypt_event(self, evt: Event) -> Event:
        pass

