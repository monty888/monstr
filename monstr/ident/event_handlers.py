from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.client.client import Client
from datetime import datetime
import logging
import copy
from abc import ABC, abstractmethod
from monstr.ident.profile import Profile, ProfileList, Keys
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
    def get_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
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
    """

    def __init__(self, cache):
        self._cache = cache

    def do_event(self, the_client: Client, sub_id: str, evts: Event):
        if isinstance(evts, Event):
            evts = [evts]
        evts = Event.latest_events_only(evts, kind=Event.KIND_META)
        c_evt: Event
        p: Profile
        for c_evt in evts:
            p = Profile.from_event(c_evt)
            if p.public_key not in self._cache or \
                    (p.public_key in self._cache and
                     self._cache[p.public_key].update_at < p.update_at):
                self._cache[p.public_key] = p
                logging.info('ProfileEventHandler::do_event cache updated pub_k - %s' % p.public_key)

    def have_profile(self, pub_k):
        return self._cache is not None and pub_k in self._cache

    def get_profile(self, pub_k:str, create_missing=False) -> Profile:
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
                 cache):
        self._client = client
        super().__init__(cache)

    def _fetch_profiles(self, pub_ks) -> [Profile]:
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

        meta_events = self._client.query(
            filters=q,
            # cache will be updating in do_event
            do_event=self.do_event,
            # note this means data will be return as quick as your slowest relay...
            emulate_single=True)

        Event.latest_events_only(meta_events, kind=Event.KIND_META)
        return [Profile.from_event(evt) for evt in meta_events]

    def get_profile(self, pub_k, create_missing=False):
        ret = super().get_profile(pub_k,
                                  create_missing=False)
        # if we don't already have then we'll try and fetch from client
        if ret is None:
            fetched_meta = self._fetch_profiles([pub_k])
            if fetched_meta:
                ret = fetched_meta[0]
            elif create_missing:
                ret = self.create_missing(pub_k)
                # will have to manually put this fake in... It's just there
                # so we don't keep going to the network for meta that doesn't exist
                self._cache[pub_k] = ret

        return ret

    def get_profiles(self, pub_ks: [str], create_missing=False) -> ProfileList:
        for_keys = self.get_hex_keys(pub_ks)
        ret = []
        if for_keys:
            # those we have
            ret = [self.get_profile(k) for k in for_keys if k in self]

            to_fetch = [k for k in for_keys if k not in self]
            to_fetch.sort()
            fetched_p = self._fetch_profiles(to_fetch)
            ret = ret + fetched_p

            # add placeholders for any we don't have if createmissing
            # this does't include invalid keys
            if create_missing:
                ret = ret + [self.create_missing(k) for k in for_keys if k not in self]

        return ProfileList(ret)

