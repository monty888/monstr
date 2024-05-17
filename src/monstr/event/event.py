from datetime import datetime
import json
import logging
from json import JSONDecodeError
import secp256k1
import hashlib
from copy import copy
from monstr.util import util_funcs


class EventTags:
    """
        split out so we can use event tags without have to create the whole event
    """
    def __init__(self, tags):
        self.tags = tags

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, tags):

        # if passed in as json str e.g. as event is received over ws
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except JSONDecodeError as je:
                tags = None

        if tags is None:
            tags = []
        self._tags = tags

    def get_tags(self, tag_name: str):
        """
        returns tag data for tag_name, no checks on the data e.g. that #e, event id is long enough to be valid event
        :param tag_name:
        :return:
        """
        return [t[1:] for t in self._tags if len(t) >= 1 and t[0] == tag_name]

    def get_tags_value(self, tag_name: str) -> []:
        """
        returns [] containing the 1st value field for a given tag, in many cases this is all we want
        if not use get_tags
        :param tag_name:
        :return:
        """
        return [t[0] for t in self.get_tags(tag_name)]

    def get_tag_value_pos(self, tag_name: str, pos: int = 0, default: str = None) -> str:
        """
            returns tag value (first el after tag name) for given tag_name at pos,
            if there isn't a tag at that pos then default is returned

            e.g. we only want very first d tags value else ''
                get_tag_value_pos('d', default='')

        """
        ret = default
        vals = self.get_tags_value(tag_name)
        if vals:
            ret = vals[pos]
        return ret

    @property
    def tag_names(self) -> set:
        # return all unique tag names
        return {c_tag[0] for c_tag in self._tags if len(c_tag)>0}

    @property
    def e_tags(self):
        """
        :return: all ref'd events/#e tag in [evt_id, evt_id,...] makes sure evt_id is correct len
        """
        return [t[0] for t in self.get_tags('e') if len(t[0]) == 64]

    @property
    def p_tags(self):
        """
        :return: all ref'd profile/#p tag in [pub_k, pub_k,...] makes sure pub_k is correct len
        """
        return [t[0] for t in self.get_tags('p') if len(t[0]) == 64]

    def __str__(self):
        return json.dumps(self._tags)

    def __len__(self):
        return len(self._tags)

    def __getitem__(self, item):
        return self._tags[item]

    def __iter__(self):
        for c_tag in self._tags:
            yield c_tag

class Event:
    """
        base class for nost events currently used just as placeholder for the kind type consts
        likely though that we'll subclass and have some code where you actually create and use these
        events. Also make so easy to sign and string and create from string

    """
    KIND_META = 0
    KIND_TEXT_NOTE = 1
    KIND_RELAY_REC = 2
    KIND_CONTACT_LIST = 3
    KIND_ENCRYPT = 4
    KIND_DELETE = 5
    # NIP 25 reactions https://github.com/nostr-protocol/nips/blob/master/25.md
    KIND_REACTION = 7
    # NIP 58 badges https://github.com/nostr-protocol/nips/pull/229
    KIND_BADGE = 8

    # NIP59 seal and gift wrap as defined in  https://github.com/nostr-protocol/nips/blob/master/59.md
    KIND_SEAL = 13
    KIND_RUMOUR = 14
    KIND_GIFT_WRAP = 1059

    # NIP 28 events for group chat
    # https://github.com/nostr-protocol/nips/blob/af6893145f9a4a63be3d90beffbcfd4d90e872ae/28.md
    KIND_CHANNEL_CREATE = 40
    KIND_CHANNEL_META = 41
    KIND_CHANNEL_MESSAGE = 42
    KIND_CHANNEL_HIDE = 43
    KIND_CHANNEL_MUTE = 44

    # nip 98 http auth header event https://github.com/nostr-protocol/nips/blob/master/98.md
    KIND_HTTP_AUTH = 27235

    # nip42 auth event https://github.com/nostr-protocol/nips/blob/master/42.md
    KIND_AUTH = 22242

    # a wrapped event to be republished see https://github.com/motorina0/nips/blob/republish_events/705.md
    KIND_REPUBLISH = 20001

    # a raw bitcoin transaction
    KIND_BTC_TX = 28333

    # user status events https://github.com/nostr-protocol/nips/blob/master/38.md
    KIND_USER_STATUS = 30315

    # @staticmethod
    # def from_JSON(evt_json):
    #     # TODO: remove!!!! change to using load in place
    #     # this was never really from json anway it's from dict
    #     return Event(
    #         id=evt_json['id'],
    #         sig=evt_json['sig'],
    #         kind=evt_json['kind'],
    #         content=evt_json['content'],
    #         tags=evt_json['tags'],
    #         pub_key=evt_json['pubkey'],
    #         created_at=evt_json['created_at']
    #     )

    @staticmethod
    def load(event_data: str | dict, validate=False) -> 'Event':
        """
            return a Event object either from a dict or json str this replaces the old from_JSON method
            that was actually just from a string...
            if validate is set True will test the event sig, if it's not None will be returned

        """
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except Exception as e:
                event_data = {}

        id = None
        if 'id' in event_data:
            id = event_data['id']

        sig = None
        if 'sig' in event_data:
            sig = event_data['sig']

        kind = None
        if 'kind' in event_data:
            kind = event_data['kind']

        content = None
        if 'content' in  event_data:
            content = event_data['content']

        tags = None
        if 'tags' in event_data:
            tags = event_data['tags']

        pub_key = None
        if 'pubkey' in event_data:
            pub_key = event_data['pubkey']

        created_at = None
        if 'created_at' in event_data:
            created_at = event_data['created_at']

        ret = Event(
            id=id,
            sig=sig,
            kind=kind,
            content=content,
            tags=tags,
            pub_key=pub_key,
            created_at=created_at
        )

        # None ret if validating and the evnt is not valid
        if validate is True and ret.is_valid() is False:
            ret = None

        return ret


    @staticmethod
    def is_event_id(event_id: str):
        """
        basic check that given str is a monstr event id
        """
        ret = False
        if len(event_id) == 64:
            # and also hex, will throw otherwise
            try:
                bytearray.fromhex(event_id)
                ret = True
            except:
                pass
        return ret

    @staticmethod
    def merge(*args):
        """
        from []... of events return a single [] with only the unique events
        :param args: [Events], [Events] events can either be as Event or {}
        but if they're mixed they'll be mixed in the ret too
        :return: [Events]
        """
        ret = []
        have = set()
        c_evt: Event
        for c_evt_set in args:
            for c_evt in c_evt_set:
                if isinstance(c_evt, Event):
                    id = c_evt.id
                else:
                    id = c_evt['id']

                if id not in have:
                    ret.append(c_evt)
                    have.add(id)
        return ret

    @staticmethod
    def sort(evts: [], reverse=True, inplace=False):
        """
        :param evts:    events to be sorted either {} or Event
        :param reverse: True is newest first which is default
        :param inplace: act on evts or create new []
        :return: sorted events

        NOTE - if you're only working with events and inplace is fine you can just use standard python sort
        i.e
            evts = [Events]
            evts.sort()

        """
        # sort events newest to oldest
        def sort_func(evt: Event):
            if isinstance(evt, Event):
                ret = evt.created_at_ticks
            else:
                ret = evt['created_at']
            return ret

        # default same arr
        if inplace:
            evts.sort(key=sort_func, reverse=reverse)
        else:
            evts = sorted(evts, key=sort_func, reverse=reverse)
        return evts

    @staticmethod
    def latest_events_only(evts: [], kind=None):
        """
        use with events where only the latest event matters for example contact, profile updates
        the relay may do this (probably should have) but just incase
        where kind is not supplied it;ll be taken from the first event
        :param evts:
        :param kind: the kind we're interested in
        :return:
        """
        if not evts:
            return []

        sorted = Event.sort(evts, inplace=False)
        if kind is None:
            kind = evts[0].kind

        ret = []
        since_lookup = set()

        c_evt: Event
        for c_evt in sorted:
            if c_evt.kind == kind and c_evt.pub_key not in since_lookup:
                since_lookup.add(c_evt.pub_key)
                ret.append(c_evt)
            elif c_evt.kind == kind:
                logging.debug('latest_events_only: ignore superceeded event %s' % c_evt)

        return ret

    def __init__(self, id=None, sig=None, kind=None, content=None, tags=None, pub_key=None, created_at=None):
        self._id = id
        self._sig = sig
        self._kind = kind
        self._created_at = created_at
        # normally the case when creating a new event
        if created_at is None:
            self._created_at = util_funcs.date_as_ticks(datetime.now())
        elif isinstance(self._created_at, datetime):
            self._created_at = util_funcs.date_as_ticks(self._created_at)

        # content forced to str
        self._content = str(content)

        self._pub_key = pub_key

        if isinstance(tags, EventTags):
            # TODO - change to copy instead of same obj?
            self._tags = tags
        else:
            self._tags = EventTags(tags)

    def serialize(self):
        """
            see https://github.com/fiatjaf/nostr/blob/master/nips/01.md
        """
        if self._pub_key is None:
            raise Exception('Event::serialize can\'t be done unless pub key is set')

        ret = json.dumps([
            0,
            self._pub_key,
            self._created_at,
            self._kind,
            self._tags.tags,
            self._content
        ], separators=(',', ':'), ensure_ascii=False)

        return ret

    def _get_id(self):
        """
            see https://github.com/fiatjaf/nostr/blob/master/nips/01.md
            pub key must be set to generate the id
        """
        evt_str = self.serialize()
        self._id = hashlib.sha256(evt_str.encode('utf-8')).hexdigest()

    def _invalidate(self):
        # should be called on any property set, as this will no longer be valid
        self._id = None
        self._sig = None

    def sign(self, priv_key):
        """
            see https://github.com/fiatjaf/nostr/blob/master/nips/01.md
            pub key must be set to generate the id

            if you were doing we an existing event for some reason you'd need to change the pub_key
            as else the sig we give won't be as expected
            Eventually it might be move this into signer and always exepct use of signer...
        """
        self._get_id()

        # pk = secp256k1.PrivateKey(priv_key)
        pk = secp256k1.PrivateKey()
        pk.deserialize(priv_key)

        # sig = pk.ecdsa_sign(self._id.encode('utf-8'))
        # sig_hex = pk.ecdsa_serialize(sig).hex()
        id_bytes = (bytes(bytearray.fromhex(self._id)))
        sig = pk.schnorr_sign(id_bytes, bip340tag='', raw=True)
        sig_hex = sig.hex()

        self._sig = sig_hex

    def is_valid(self):
        pub_key = secp256k1.PublicKey(bytes.fromhex('02'+self._pub_key),
                                      raw=True)

        ret = pub_key.schnorr_verify(
            msg=bytes.fromhex(self._id),
            schnorr_sig=bytes.fromhex(self._sig),
            bip340tag='', raw=True)

        return ret

    def data(self):
        return {
            'id': self._id,
            'pubkey': self._pub_key,
            'created_at': self._created_at,
            'kind': self._kind,
            'tags': self._tags.tags,
            'content': self._content,
            'sig': self._sig
        }

    def test(self, filter):
        # where ttype is [e]vent or [p]ubkey
        def _test_tag_match(t_type, single_filter):
            ismatch = False
            # create lookup of out type tags
            t_lookup = set()
            for c_tag in self._tags:
                if c_tag and c_tag[0] == t_type and len(c_tag) > 1:
                    t_lookup.add(c_tag[1])
            # if there are any p tags on this event
            if t_lookup:
                # just incase has been passed as str
                t_filter = single_filter['#'+t_type]
                if not isinstance(t_filter, list):
                    t_filter = [str(t_filter)]

                for c_t in t_filter:
                    if c_t in t_lookup:
                        ismatch = True
                        break

            return ismatch

        def _field_tag_match(name, single_filter):
            field_match = False
            if name not in c_filter:
                field_match = True
            else:
                to_test = single_filter[name]
                if isinstance(to_test, str):
                    to_test = [to_test]

                for c_test in to_test:
                    if name == 'authors' and self.pub_key.startswith(c_test):
                        field_match = True
                        break
                    elif name == 'ids' and self.id.startswith(c_test):
                        field_match = True
                        break

            return field_match

        if isinstance(filter, dict):
            filter = [filter]

        for c_filter in filter:
            ret = True
            if 'since' in c_filter and self.created_at_ticks <= c_filter['since']:
                ret = False
            if 'until' in c_filter and self.created_at_ticks >= c_filter['until']:
                ret = False
            if 'kinds' in c_filter:
                fkinds = c_filter['kinds']
                if hasattr(fkinds, '__iter__'):
                    if self.kind not in fkinds:
                        ret = False
                elif fkinds != self.kind:
                    ret = False
            if not _field_tag_match('authors', c_filter):
                ret = False
            if not _field_tag_match('ids', c_filter):
                ret = False

            # generic tags start with #, also included here are p and e tags as they're done in same way
            for c_name in c_filter:
                # its an event tag
                if c_name[0] == '#':
                    if not _test_tag_match(c_name[1:], c_filter):
                        ret = False

            # multiple filters are joined so a pass on any and we're out of here
            if ret:
                break

        return ret

    def is_replacable(self) -> bool:
        # true if replacable as defined by NIP16 https://github.com/nostr-protocol/nips/blob/master/16.md
        return self.kind in (Event.KIND_META, Event.KIND_CONTACT_LIST) or \
               (10000 <= self.kind < 20000)

    def is_ephemeral(self) -> bool:
        # true if emphereal as defined by NIP16
        return 20000 <= self.kind < 30000

    def is_parameter_replacable(self) -> bool:
        # true if replacable as defined by NIP33 https://github.com/nostr-protocol/nips/blob/master/33.md
        return 30000 <= self.kind < 40000

    @property
    def tags(self):
        return self._tags

    @tags.setter
    def tags(self, tags):
        self._invalidate()
        # already a EventTags obj
        if isinstance(tags, EventTags):
            self._tags = tags
        # should be [[]]
        else:
            self._tags = EventTags(tags)

    def get_tags(self, tag_name):
        return self._tags.get_tags(tag_name)

    def get_tags_value(self, tag_name):
        return self._tags.get_tags_value(tag_name)

    def get_tag_value_pos(self, tag_name: str, pos: int = 0, default: str = None) -> str:
        return self._tags.get_tag_value_pos(tag_name=tag_name,
                                            pos=pos,
                                            default=default)

    @property
    def e_tags(self):
        return self._tags.e_tags

    @property
    def p_tags(self):
        return self._tags.p_tags


    """
        get/set various event properties
        Note changing is going to make event_data that has been signed incorrect, probably the caller should be aware
        of this but might do something to make this clear 

    """

    @property
    def pub_key(self):
        return self._pub_key

    @pub_key.setter
    def pub_key(self, pub_key):
        self._invalidate()
        self._pub_key = pub_key

    @property
    def id(self):
        if self._id is None:
            self._get_id()
        return self._id

    @property
    def short_id(self):
        # shorter version of id for display, note id doesn't until signing
        return util_funcs.str_tails(self.id, 4)

    @property
    def created_at(self) -> datetime:
        return util_funcs.ticks_as_date(self._created_at)

    @created_at.setter
    def created_at(self, dt):
        self._invalidate()
        if dt is None or not isinstance(dt, (datetime, int)):
            raise ValueError(f'Event::created_at: invalid value for created_at - {dt}')
        elif isinstance(dt, datetime):
            self._created_at = util_funcs.date_as_ticks(dt)
        elif isinstance(dt, int):
            self._created_at = dt

    @property
    def created_at_ticks(self):
        return self._created_at

    @property
    def kind(self) -> int:
        return self._kind

    @kind.setter
    def kind(self, kind: int):
        self._invalidate()
        self._kind = kind

    @property
    def content(self) -> str:
        return self._content

    @content.setter
    def content(self, content):
        self._invalidate()
        self._content = content

    @property
    def sig(self):
        return self._sig

    def __str__(self):
        ret = super(Event, self).__str__()
        # hopefully id is set but it might not be if the event is being prepeped
        # perhaps we should check pubkey here instead because if that exists we can gen the id
        if self._id is not None:
            ret = f'{self.id}@{self.created_at}'
        return ret

    def add_pow(self, target: int = 4):
        if target < 4 or target > 64:
            raise ValueError(f"target should be in range 4 to 64 got {target}")

        val = 0
        leading_z = 0
        original_tags = self.tags.tags[:]
        nonce_template = original_tags + [['nonce', '', f'{target}']]

        while leading_z < target:
            nonce_template[-1][1] = f'{val}'
            self.tags = nonce_template

            # Directly convert the hexadecimal id to an integer and calculate leading zeros
            leading_z = (256 - int(self.id, 16).bit_length())
            val += 1

    @property
    def pow(self):
        # returns the events pow value - not necessarily targeted
        return 256 - int(self.id, 16).bit_length()

    def nip13_valid_pow(self, min_pow):
        """
            returns True if this event has valid targeted pow and that pow is >= min_pow
            https://github.com/nostr-protocol/nips/blob/master/13.md
            NOTE you also need to check if the event is valid!
        """
        ret = False
        pow_value = self.pow
        try:
            nonce = self.get_tags('nonce')[0][1]
            target_pow = int(nonce)
            ret = pow_value >= target_pow >= min_pow
        except Exception as e:
            pass
        return ret

    def __lt__(self, other: 'Event'):
        # added so we can support basic sorting, newest events will be first
        ret = True
        if self.created_at_ticks < other.created_at_ticks:
            ret = False
        return ret

