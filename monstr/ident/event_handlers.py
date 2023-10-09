from __future__ import annotations

import sys
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.client.client import Client

from datetime import datetime
import logging
from cachetools import TTLCache, LRUCache
from abc import ABC, abstractmethod
from monstr.ident.profile import Profile, ProfileList, Keys, ContactList
from monstr.ident.persist import ProfileStoreInterface
from monstr.event.event import Event
from monstr.util import util_funcs


class ProfileEventHandlerInterface(ABC):

    @abstractmethod
    def do_event(self, the_client: Client, sub_id: str, evts: Event):
        pass

    @abstractmethod
    def have_profile(self, pub_k):
        pass

    @abstractmethod
    def get_profile(self, pub_k: str, create_missing=False) -> Profile:
        pass

    @abstractmethod
    async def aget_profile(self, pub_k: str, create_missing=False) -> Profile:
        pass

    @abstractmethod
    def get_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
        pass

    @abstractmethod
    async def aget_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
        pass

    @abstractmethod
    async def aload_contacts(self, p: str | Profile) -> ContactList:
        pass

    @staticmethod
    def get_hex_keys(pub_ks):
        """
        :param pub_ks:
        :return: from the given pub_ks will return only those that are valid, in hex format
        """
        ret = set()
        if isinstance(pub_ks, str):
            pub_ks = [pub_ks]

        for k in pub_ks:
            if Keys.is_hex_key(k):
                ret.add(k)
            elif k.startswith('npub') and Keys.is_bech32_key(k):
                ret.add(Keys.hex_key(k))
        return list(ret)

    def create_missing(self, pub_k):
        # use to return a placeholder profile
        return Profile(pub_k=pub_k,
                       update_at=datetime(1970, 1, 1),
                       attrs={})

    def __contains__(self, item):
        return self.have_profile(item)

    def __getitem__(self, item):
        ret = None
        if self.have_profile(item):
            ret = self.get_profile(item)
        return ret


class ProfileEventHandler(ProfileEventHandlerInterface):
    """
        simplified profile event handler -  this handler won't ever fetch profiles itself
        so they need to have been put there via the do_event method having been called
        or previously persisted into a given store
    """

    def __init__(self,
                 cache=None,
                 store: ProfileStoreInterface = None):
        # 10000 least recently used
        # should be ok for most uses - better to use networked for most cases anyway
        # unless maybe you want to control the fetches yourself
        if cache is None:
            cache = LRUCache(maxsize=10000)
        # a cache for quick access now
        self._cache = cache
        # this is storage e.g. db that we'd expect to persist across runs
        self._store = store

    def do_event(self, the_client: Client, sub_id: str, evts: Event):
        if isinstance(evts, Event):
            evts = [evts]
        meta_evts = Event.latest_events_only(evts, kind=Event.KIND_META)
        c_evt: Event
        p: Profile
        to_put = []
        # update metas
        for c_evt in meta_evts:

            p = Profile.from_event(c_evt)
            if p.public_key not in self._cache or \
                    (p.public_key in self._cache and
                     self._cache[p.public_key].update_at < p.update_at):


                self._cache[p.public_key] = p


                to_put.append(p)
                logging.info('ProfileEventHandler::do_event cache updated profile pub_k - %s/%s' % (p.public_key,
                                                                                                    p.name))

        # update contacts.. note only done if we have a profile in the cache
        contact_evts = Event.latest_events_only(evts, kind=Event.KIND_CONTACT_LIST)
        for c_evt in contact_evts:
            if self._in_cache(c_evt.pub_key):
                p = self._cache[c_evt.pub_key]
                p.contacts = ContactList.from_event(c_evt)
                logging.info('ProfileEventHandler::do_event cache updated contacts pub_k - %s/%s' % (p.public_key,
                                                                                                     p.name))

        if to_put and self._store:
            self._store.put_profile(to_put)

    def _in_cache(self, pub_k):
        return pub_k in self._cache

    def _in_store(self, pub_k):
        ret = False
        if self._store:
            profiles = self._store.select_profiles({
                'public_key': pub_k
            })
            if profiles:
                ret = True
                p = profiles[0]
                self._cache[p.public_key] = p

        return ret

    def have_profile(self, pub_k):
        return self._in_cache(pub_k) or self._in_store(pub_k)

    def get_profile(self, pub_k: str, create_missing=False) -> Profile:
        # if npub convert to hex
        if pub_k.startswith('npub') and Keys.is_bech32_key(pub_k):
            pub_k = Keys.hex_key(pub_k)

        ret = None
        if pub_k in self:
            ret = self._cache[pub_k]
        elif create_missing and Keys.hex_key(pub_k):
            ret = Profile(pub_k=pub_k,
                          update_at=datetime(1970, 1, 1),
                          attrs={
                              'name': 'not found'
                          })
            # put into the cache - it has an old date so hopefully will be replaced as
            # soon as we get a upto date meta
            self._cache[pub_k] = ret

        return ret

    def get_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
        """
        for getting mutiple profiles
        :param pub_ks:
        :param create_missing:
        :return:
        """
        ret = []
        for_keys = self.get_hex_keys(pub_ks)
        for k in for_keys:
            ret.append(self.get_profile(k,
                                        create_missing=create_missing))

        return ProfileList(ret)


class NetworkedProfileEventHandler(ProfileEventHandler):
    """
        simplified profile handler to replace what we have in ident/event_handlers
    """
    def __init__(self,
                 client: Client,
                 cache=None,
                 store: ProfileStoreInterface = None):
        self._client = client
        # default of 10000 with 1hr timeout at which point it'll go to the network
        if cache is None:
            cache = TTLCache(maxsize=10000,
                             ttl=60*60)

        super().__init__(cache, store)

    async def _fetch_profiles(self, pub_ks) -> [Profile]:
        if not pub_ks:
            return []

        q = []
        for c_pub_ks in util_funcs.chunk(pub_ks, 200):
            q.append(
                {
                    'authors': c_pub_ks,
                    'kinds': [Event.KIND_META]
                }
            )

        meta_events = await self._client.query(
            filters=q,
            # cache will be updating in do_event
            do_event=self.do_event,
            # note this means data will be return as quick as your slowest relay...
            emulate_single=True)

        meta_events = Event.latest_events_only(meta_events, kind=Event.KIND_META)
        return [Profile.from_event(evt) for evt in meta_events]

    async def _fetch_contacts(self, pub_ks) -> [ContactList]:
        if not pub_ks:
            return None

        q = []
        for c_pub_ks in util_funcs.chunk(pub_ks, 200):
            q.append(
                {
                    'authors': c_pub_ks,
                    'kinds': [Event.KIND_CONTACT_LIST]
                }
            )

        con_events = await self._client.query(
            filters=q,
            do_event=self.do_event,
            emulate_single=True)

        Event.latest_events_only(con_events, kind=Event.KIND_CONTACT_LIST)
        return [ContactList.from_event(evt) for evt in con_events]

    async def aget_profile(self, pub_k, create_missing=False):
        ret = super().get_profile(pub_k,
                                  create_missing=False)
        # if we don't already have then we'll try and fetch from client
        if ret is None:
            fetched_meta = await self._fetch_profiles([pub_k])
            if fetched_meta:
                ret = fetched_meta[0]
            elif create_missing:
                ret = self.create_missing(pub_k)
                # will have to manually put this fake in... It's just there
                # so we don't keep going to the network for meta that doesn't exist
                self._cache[pub_k] = ret

        return ret

    async def aget_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
        for_keys = self.get_hex_keys(pub_ks)
        ret = []
        if for_keys:
            # those we have
            ret = [self.get_profile(k) for k in for_keys if k in self]

            to_fetch = [k for k in for_keys if k not in self]
            to_fetch.sort()
            fetched_p = await self._fetch_profiles(to_fetch)
            ret = ret + fetched_p

            # add placeholders for any we don't have if createmissing
            # this does't include invalid keys

            if create_missing:
                p: Profile
                have = set([p.public_key for p in ret])
                for k in to_fetch:
                    if k not in have:
                        n_p = self.create_missing(k)
                        ret.append(n_p)
                        self._cache[k] = n_p
        return ProfileList(ret)

    async def aload_contacts(self, p: str | Profile) -> ContactList:
        if isinstance(p, Profile):
            pub_key = p.public_key
        else:
            pub_key = p

        # load the contacts
        p_contacts = await self._fetch_contacts(pub_ks=[pub_key])

        # we'll return a ContatcList no matter what, empty if we didn't get anything
        ret = p_contacts
        if p_contacts:
            ret = p_contacts[0]
        # couldn't find any?
        else:
            ret = ContactList(contacts=[],
                              owner_pub_k=pub_key)

        # if called with profile then we'll set contacts on that profile
        if isinstance(p, Profile):
            p.contacts = ret

        return ret
