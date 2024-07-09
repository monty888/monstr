from abc import ABC, abstractmethod
import datetime
import logging
import asyncio
import json
from json import JSONDecodeError
from urllib.parse import urlparse, parse_qs
from monstr.client.client import ClientPool, Client
from monstr.encrypt import Keys, Encrypter
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

# some basic authorisers
class AuthoriseAll(NIP46AuthoriseInterface):

    def __init__(self, auth_info: callable = None):
        self._auth_info = auth_info

    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        if self._auth_info:
            await self._auth_info(method, id, params)
        return True


class RequestAuthorise(NIP46AuthoriseInterface):

    def __init__(self,
                 request_auth: callable,
                 auth_info: callable = None):

        self._request_auth = request_auth
        self._auth_info = auth_info

    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        if self._auth_info:
            await self._auth_info(method, id, params)

        return await self._request_auth(method, id, params)


class TimedAuthorise(NIP46AuthoriseInterface):

    def __init__(self,
                 request_auth: callable,
                 auth_info: callable = None,
                 auth_mins = 10):

        self._auth_info = auth_info
        self._do_request_auth = RequestAuthorise(request_auth=request_auth)

        self._last_auth_at = None
        self._auth_delta = datetime.timedelta(minutes=auth_mins)

    async def authorise(self, method: str, id: str, params: [str]) -> bool:
        now = datetime.datetime.now()

        # maybe we need to reauth?
        if self._last_auth_at is None or (now - self._last_auth_at) > self._auth_delta:
            ret = await self._do_request_auth.authorise(method, id, params)
            if ret:
                self._last_auth_at = now
        else:
            ret = True
            if self._auth_delta:
                await self._auth_info(method, id, params)

        return ret


class NIP46Comm(EventHandler, ABC):

    def __init__(self,
                 relay: [str],
                 on_command: callable = None,
                 on_response: callable = None,
                 comm_signer: SignerInterface = None):

        # I don't see why this needs to be the same key as we're signer for, but atleast with
        # nostrudel as far as I can tell it does to get it to work.. else you end up signing in#
        # as the comm key...
        self._comm_signer = comm_signer
        if comm_signer is None:
            self._comm_signer = BasicKeySigner(Keys())

        # relays we'll attach too
        self._relay = relay
        if isinstance(relay, str):
            self._relay = [relay]

        # maybe could execept client objs but just makes things cleaner if we only use our own client obj
        for i in range(0, len(self._relay)):
            if not isinstance(self._relay[i],str):
                raise ValueError(f'NIP46Comm::__init__: should be str got {self._relay[i]}')

        self._client = ClientPool(relay)
        self._run = False

        # events queued and dealt with serially as they come in
        self._event_q: asyncio.Queue = asyncio.Queue()
        # start a process to work on the queued events
        self._event_process_task = asyncio.create_task(self._my_event_consumer())

        # called when we see method events - most likely when we're acting as signer
        self._on_command = on_command

        # called when we see response events - most likely when we're signer client
        self._on_response = on_response

        super().__init__(event_acceptors=[
            DeduplicateAcceptor()
        ])

    @property
    async def bunker_url(self):
        return f'bunker://{await self._comm_signer.get_public_key()}?relay={"&".join(self._relay)}'

    @property
    async def bunker_key(self):
        return await self._comm_signer.get_public_key()

    @property
    def running(self) -> bool:
        return self._run

    async def _get_msg_event(self, content: str, to_k: str) -> Event:
        # returns encrypted and signed method for content
        # encrypt the content
        content = await self._comm_signer.nip4_encrypt(content, to_pub_k=to_k)

        # make the event
        ret = Event(pub_key=await self._comm_signer.get_public_key(),
                    kind=Event.KIND_NIP46,
                    content=content,
                    tags=[
                        ['p', to_k]
                    ]
                )
        # and sign it
        await self._comm_signer.sign_event(ret)

        return ret

    async def _my_event_consumer(self):
        # listen to event to us and call back the handler as we get commands
        while self._run:
            try:
                args = await self._event_q.get()
                await self.ado_event(*args)
            except Exception as e:
                logging.debug(f'NIP46Comm::_my_event_consumer: {e}')

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
        # pull of events that were put on the queue bu do_event and deal with them
        decrypted_evt = await self._comm_signer.nip4_decrypt_event(evt)
        try:
            cmd_dict = json.loads(decrypted_evt.content)
            if 'method' in cmd_dict and self._on_command:
                id = cmd_dict['id']
                method = cmd_dict['method']
                params = cmd_dict['params']

                result, err = await self._on_command(id, method, params, evt)
                to_k = evt.pub_key
                await self._do_response(result, err, to_k, id)
            elif 'result' in cmd_dict and self._on_response:
                await self._on_response(cmd_dict)
            else:
                logging.debug(f'NIP46Comm::ado_event - ignored event with contents - {cmd_dict}')

        except Exception as e:
            logging.debug(f'NIP46Comm::ado_event {e}')

    async def _do_response(self,
                           result: str,
                           error: str,
                           to_k: str,
                           id: str = None):
        if id is None:
            id = util_funcs.get_rnd_hex_str(8)
        evt = await self._get_msg_event(json.dumps({
            'id': id,
            'result': result,
            'error': error
        }), to_k)
        self._client.publish(evt)

    async def do_request(self, method: str, params: [str], to_k, id: str = None):
        if id is None:
            id = util_funcs.get_rnd_hex_str(8)

        content = json.dumps({
            'id': id,
            'method': method,
            'params': params
        })

        evt = await self._get_msg_event(
            content=content,
            to_k=to_k
        )
        self._client.publish(evt)

        return id

    def run(self, on_status=None) -> ClientPool:
        self._run = True

        # make client obj that will actually do the comm
        async def aconnect(my_client: Client):
            # sub any NIP46 events to our pub_k
            my_client.subscribe(
                handlers=[self],
                filters={
                    '#p': [await self._comm_signer.get_public_key()],
                    'kinds': [Event.KIND_NIP46]
                }
            )

        def on_connect(my_client: Client):
            asyncio.create_task(aconnect(my_client))

        self._client.set_on_connect(on_connect)
        self._client.set_on_status(on_status)
        asyncio.create_task(self._client.run())

        return self._client

    def end(self):
        self._run = False
        self._client.end()

    @property
    def client(self) -> ClientPool:
        return self._client

    async def __aenter__(self):
        self.run()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.end()


class NIP46ServerConnection:
    """
        this is the server side of a NIP46 signing process.
        It'll listens and signs events on behalf of a client that requests it so that the
        client never holds the keys itself.
    """
    def __init__(self,
                 signer: SignerInterface,
                 relay: [str],
                 authoriser: NIP46AuthoriseInterface = None,
                 same_signer_for_comm: bool = True):

        # this is the key we'll sign as
        self._signer = signer

        self._comm_sign = None
        # it's probably better to use a rnd key for the signing comm but some services don't seem to
        # like this
        if same_signer_for_comm:
            self._comm_sign = self._signer

        # this is the chanel we sign over
        self._comm = NIP46Comm(relay=relay,
                               comm_signer=self._comm_sign,
                               on_command=self._do_command)

        # called before we do any method
        self._authoriser = authoriser

        # all keys that are connected
        self._connections = set()

        # call run to start, do it via asyncio.create_task if you want to
        # do something else at same time, make sure to call end() when done
        self._run = False


    @property
    async def bunker_url(self):
        # this will be different every time we're run
        return await self._comm.bunker_url

    def _connected(self, connection_key: str) -> bool:
        return connection_key in self._connections

    def _check_con(self, evt: Event, method: str):
        connect_key = evt.pub_key
        if not self._connected(connect_key):
            raise SignerException(f'NIP46ServerConnection::{method}: not connected! {connect_key}')

    async def describe(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        self._check_con(evt, 'describe')

        return json.dumps(['describe',
                           'get_public_key',
                           'sign_event',
                           'nip04_encrypt',
                           'nip04_decrypt',
                           'connect']
                          ), ''

    # async def request_connect(self):
    #     await self._do_command('connect', [await self._signer.get_public_key()])

    async def connect(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        if not params:
            raise SignerException('NIP46ServerConnection::connect: connection key is required')
        connect_key = params[0]
        if not Keys.is_valid_key(connect_key):
            raise SignerException(f'NIP46ServerConnection::connect: invalid key {connect_key}')
        if self._connected(connect_key):
            raise SignerException(f'NIP46ServerConnection::connect: already connected! {connect_key}')

        self._connections.add(connect_key)
        return await self._signer.get_public_key(), ''

    async def get_public_key(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        self._check_con(evt, 'get_public_key')
        return await self._signer.get_public_key(), ''

    async def _do_encrypt(self, id: str, params: [str], evt: Event, enc_name: str, enc_func: callable) -> tuple[str, str]:
        self._check_con(evt, enc_name)
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::{enc_name}: requires 2 params got {n_params} - to key and plain text')

            to_k = params[0]
            plain_text = params[1]
            if not Keys.is_hex_key(to_k):
                raise SignerException(
                    f'Signer::{enc_name}: to key is not valid - {to_k}')

            ciper_text = await enc_func(plain_text=plain_text,
                                        to_pub_k=to_k)

            return ciper_text, ''

        except SignerException as se:
            return '', str(se)

        except Exception as e:
            return '', (f'Signer::{enc_name}: unable to encrypt as '
                        f'{await self._signer.get_public_key()} '
                        f'error - {str(e)}')

    async def _do_decrypt(self, id: str, params: [str], evt: Event, dec_name: str, dec_func: callable) -> tuple[str, str]:
        self._check_con(evt, dec_name)
        try:
            n_params = len(params)
            if n_params < 2:
                raise SignerException(
                    f'Signer::{dec_name}: requires 2 params got {n_params} - from key and ciper text')

            from_k = params[0]
            payload = params[1]
            if not Keys.is_hex_key(from_k):
                raise SignerException(
                    f'Signer::{dec_name}: from key is not valid - {from_k}')

            plain_text = await dec_func(payload=payload,
                                        for_pub_k=from_k)

            return plain_text, ''

        except SignerException as se:
            return '', str(se)
        except Exception as e:
            return '',  (f'Signer::{dec_name}: unable to decrypt as '
                         f'{await self._signer.get_public_key()} '
                         f'error - {str(e)}')

    async def nip04_encrypt(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        return await self._do_encrypt(id, params, evt, 'nip04_encrypt', self._signer.nip4_encrypt)

    async def nip04_decrypt(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        return await self._do_decrypt(id, params, evt, 'nip04_decrypt', self._signer.nip4_decrypt)

    async def nip44_encrypt(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        return await self._do_encrypt(id, params, evt, 'nip44_encrypt', self._signer.nip44_encrypt)

    async def nip44_decrypt(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        return await self._do_decrypt(id, params, evt, 'nip44_decrypt', self._signer.nip44_decrypt)

    async def sign_event(self, id: str, params: [str], evt: Event) -> tuple[str, str]:
        self._check_con(evt, 'sign_event')
        try:
            evt_data = json.loads(params[0])
            event = Event.load(evt_data)

            await self._signer.sign_event(event)
            return json.dumps(event.data()), ''

        except JSONDecodeError as je:
            return '', f'Signer::sign_event: bad event JSON - {je}'
        except Exception as e:
            return '', f'Signer::sign_event: {e}'

    async def _do_command(self, id: str, method: str, params: [str], evt: Event) -> tuple[str, str]:
        try:
            if method in {'connect',
                          'describe',
                          'get_public_key',
                          'nip04_decrypt',
                          'nip04_encrypt',
                          'nip44_encrypt',
                          'nip44_decrypt',
                          'sign_event'}:
                logging.info(f'{method} - {params}')

                authorised = True
                if self._authoriser:
                    authorised = await self._authoriser.authorise(method, id, params)

                if authorised:
                    ret = await getattr(self, method)(id, params, evt)
                else:
                    ret = '', 'request not authorised!'
            else:
                ret = '', f'method not implemented! - {method}'

        except Exception as e:
            logging.debug(f'SignerConnection::do_command {e}')
            ret = '', str(e)

        return ret

    async def run(self, on_status: callable = None) -> ClientPool:
        self._run = True
        comm_client = self._comm.run(on_status=on_status)
        while self._run is True:
            await asyncio.sleep(0.1)
        return comm_client

    def end(self):
        self._run = False
        self._comm.end()

    @property
    def client(self) -> ClientPool:
        return self._comm.client



class NIP4SignerEncrypter(Encrypter):

    def __init__(self, signer: SignerInterface):
        self._signer = signer

    async def apublic_key_hex(self) -> str:
        return await self._signer.get_public_key()

    async def aencrypt(self, plain_text: str, to_pub_k: str) -> str:
        return await self._signer.nip4_encrypt(plain_text, to_pub_k)

    async def adecrypt(self, payload: str, for_pub_k: str) -> str:
        return await self._signer.nip4_decrypt(payload, for_pub_k)


class NIP44SignerEncrypter(Encrypter):

    def __init__(self, signer: SignerInterface):
        self._signer = signer

    async def apublic_key_hex(self) -> str:
        return await self._signer.get_public_key()

    async def aencrypt(self, plain_text: str, to_pub_k: str) -> str:
        return await self._signer.nip44_encrypt(plain_text, to_pub_k)

    async def adecrypt(self, payload: str, for_pub_k: str) -> str:
        return await self._signer.nip44_decrypt(payload, for_pub_k)


class NIP46Signer(SignerInterface):
    """
        signer that proxies signing via NIP46 - it never has access to the keys itself

        for now expects connection str, todo add where we initialise the connection
    """
    def __init__(self, connection: str,
                 auto_start=False):
        parsed = urlparse(connection)

        if parsed.scheme != 'bunker':
            raise SignerException(f'NIP46Signer::__init__: unknown connection scheme {parsed.scheme}')

        # this is the intial pk we send to to talk with the remote signer
        signer_k = parsed.netloc
        if not Keys.is_valid_key(signer_k):
            raise SignerException(f'NIP46Signer::__init__: bad key {signer_k}')
        self._signer_k = signer_k

        # this is the pub k we'll be signer as, it may be the same as signer_k
        self._sign_as_k = None

        query_parsed = parse_qs(parsed.query)
        if 'relay' not in query_parsed:
            raise SignerException(f'NIP46Signer::__init__: relay not supplied')

        # probably we should do more checks on the relay urls....
        self._relay = query_parsed['relay']

        # does the comm between us and the NIP46 server, we use ephemeral keys for signing
        self._comm = NIP46Comm(relay=self._relay,
                               on_response=self._do_response)
        if auto_start:
            self.run()

        # repsonses we waiting for key'd on id
        self._responses = {}

        # max time we'll wait before failing a response
        self._time_out = 5

    async def _do_response(self, result: dict):
        try:
            self._responses[result['id']] = result
        except Exception as e:
            logging.debug(f'NIP46Signer::_do_response {e}')

    async def _wait_response(self, id:str, time_out: int = None):
        if time_out is None:
            time_out = self._time_out

        wait_time = 0.0
        while id not in self._responses and int(wait_time) < time_out:
            await asyncio.sleep(0.1)
            wait_time += 0.1

        if id in self._responses:
            response = self._responses[id]
            if response['error']:
                raise SignerException(f'NIP46Signer::_wait_response {response["error"]}')
            else:
                return response['result']
        else:
            raise SignerException(f'NIP46Signer::_wait_response - time out waiting for response to {id}')

    async def _do_method(self, method: str, args: list) -> str:
        logging.debug(f'NIP46Signer::_do_method: {method} - {args}')

        # to_k = self._sign_as_k
        # if method == 'connect' or to_k is None:
        #     to_k = self._signer_k

        # did we already get key to connect on?
        return await self._comm.do_request(method=method,
                                           params=args,
                                           to_k=self._signer_k)

    async def _get_connect(self):
        if self._sign_as_k is None:
            id = await self._do_method('connect', [await self._comm.bunker_key])
            result = await self._wait_response(id)
            self._sign_as_k = result

    async def get_public_key(self) -> str:
        await self._get_connect()
        return self._sign_as_k

    async def sign_event(self, evt: Event):
        await self._get_connect()
        id = await self._do_method('sign_event', [json.dumps(evt.data())])
        sign_evt = Event.load(await self._wait_response(id))
        evt.id = sign_evt.id
        evt.sig = sign_evt.sig

    async def echd_key(self, to_pub_k: str) -> str:
        pass

    async def nip4_encrypt(self, plain_text: str, to_pub_k: str) -> str:
        await self._get_connect()
        id = await self._do_method('nip04_encrypt', [to_pub_k, plain_text])
        return await self._wait_response(id)

    async def nip4_decrypt(self, payload: str, for_pub_k: str) -> str:
        await self._get_connect()
        id = await self._do_method('nip04_decrypt', [for_pub_k, payload])
        return await self._wait_response(id)

    async def nip4_encrypt_event(self, evt: Event, to_pub_k: str) -> Event:
        self._enc = NIP4SignerEncrypter(self)
        return await self._enc.aencrypt_event(evt, to_pub_k)

    async def nip4_decrypt_event(self, evt: Event) -> Event:
        self._enc = NIP4SignerEncrypter(self)
        return await self._enc.adecrypt_event(evt)

    async def nip44_encrypt(self, plain_text: str, to_pub_k: str, version=2) -> str:
        await self._get_connect()
        id = await self._do_method('nip44_encrypt', [to_pub_k, plain_text])
        return await self._wait_response(id)

    async def nip44_decrypt(self, payload: str, for_pub_k: str) -> str:
        await self._get_connect()
        id = await self._do_method('nip44_decrypt', [for_pub_k, payload])
        return await self._wait_response(id)

    async def nip44_encrypt_event(self, evt: Event, to_pub_k: str) -> Event:
        self._enc = NIP44SignerEncrypter(self)
        return await self._enc.aencrypt_event(evt, to_pub_k)

    async def nip44_decrypt_event(self, evt: Event) -> Event:
        self._enc = NIP44SignerEncrypter(self)
        return await self._enc.adecrypt_event(evt)

    def run(self, on_status: callable = None) -> ClientPool:
        self._comm.run(on_status=on_status)
        return self._comm.client

    def end(self):
        self._comm.end()

    @property
    def client(self) -> ClientPool:
        return self._comm.client

    async def __aenter__(self):
        self._comm.run()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._comm.end()