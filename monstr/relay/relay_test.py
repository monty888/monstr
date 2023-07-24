"""
    tests for the monstr.relay
    TODO: this hangs because the client is not async - check again once we have asynced it.


"""
import unittest
import logging
import signal
import sys
import asyncio

from monstr.relay.relay import Relay
from monstr.event.persist_memory import RelayMemoryEventStore
from monstr.event.event import Event
from monstr.client.client import Client
import time
from monstr.encrypt import Keys


class RelayTestCase(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self) -> None:
        self._relay = None
        self._client:Client = None

        self._relay = Relay(store=RelayMemoryEventStore(),
                            enable_nip15=True)

        await self._relay.start_background(port=8887)

        # make sure relay is accepting before allowing on
        while not self._relay.started:
            time.sleep(0.1)

        self._client = Client('ws://localhost:8887')
        asyncio.create_task(self._client.run())
        await self._client.wait_connect(timeout=5)


        # key pair for tests
        k = Keys.get_new_key_pair()
        self._pub_k = k['pub_k']
        self._priv_key = k['priv_k']


    async def asyncTearDown(self) -> None:
        self._client.end()
        await self._relay.end_background()

    def _post_events(self, n_events):
        for i in range(0,n_events):
            n_evt = Event(kind=Event.KIND_TEXT_NOTE,
                          content='test_note: %s' % i,
                          pub_key=self._pub_k)
            n_evt.sign(self._priv_key)
            self._client.publish(n_evt)

    async def test_post(self):
        """
        this just posts 10 events and passes as long as that doesn't break
        if it does probably anything after this is going to break too
        :return:
        """
        self._post_events(10)
        print('test post done')

    async def test_sub(self):
        """
            test a sub by post event_count events and then adding a post to get all events
            n_count should match what we get back from the sub
        """

        # how many event we're going to test with
        event_count = 10

        self._post_events(event_count)
        ret = await self._client.query([{}])

        assert len(ret) == event_count
        print('test sub done')


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.DEBUG)
    def sigint_handler(signal, frame):
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    unittest.main()