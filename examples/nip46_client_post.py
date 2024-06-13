import asyncio
import logging
from monstr.signing.nip46 import NIP46Signer
from monstr.client.client import Client
from monstr.event.event import Event

# url to relay used for talking to the signer
RELAY = 'ws://localhost:8081'


async def do_post(url, text):
    """
        Example showing how to post a text note (Kind 1) to relay
        using nip46 signer - we don't have access locally to the keys
        here we use a with block but for long running you can also do -

        my_signer = NIP46Signer(connection=con_str, auto_start=True)

        or manually -
            my_signer = NIP46Signer(connection=con_str)
            my_signer.run()

        then call end() when done... probably you shouldn't call run on a previously ended signer...
    """

    # bunker://... e.g. printed out by nip46_signer_service.py
    con_str = input('connection string: ').strip()

    # from here it's just a signer interface same as if we were using BasicKeySigner
    async with Client(url) as c:
        async with NIP46Signer(connection=con_str) as my_signer:
            # we'll make post and they'll be signed by the bunker at con_str
            # plain text
            n_msg = await my_signer.ready_post(Event(kind=Event.KIND_TEXT_NOTE,
                                                     content=text))
            c.publish(n_msg)

            # nip4 encrypted to our self
            enc_event = Event(kind=Event.KIND_TEXT_NOTE,
                              content=text+' - encrypted nip4')
            enc_event = await my_signer.nip4_encrypt_event(enc_event,
                                                           to_pub_k=await my_signer.get_public_key())
            await my_signer.sign_event(enc_event)
            c.publish(enc_event)

            # nip44 encrypted to our self
            enc_event = Event(kind=Event.KIND_TEXT_NOTE,
                              content=text + ' - encrypted nip44')
            enc_event = await my_signer.nip44_encrypt_event(enc_event,
                                                            to_pub_k=await my_signer.get_public_key())
            await my_signer.sign_event(enc_event)
            c.publish(enc_event)


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    text = 'hello using NIP46 signer'

    asyncio.run(do_post(RELAY, text))
