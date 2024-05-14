from monstr.event.event import Event
from monstr.event.persist import EventStoreInterface, RelayEventStoreInterface,\
    StoreNIPSupport, DeleteMode, SortDirection


class MemoryEventStore(EventStoreInterface, StoreNIPSupport):
    """
        Basic event store implemented in mem using {}
        could be improved to purge old evts or at set size/number if evts
        and to pickle events on stop and load for some sort of persistence when re-run

    """

    def __init__(self,
                 delete_mode=DeleteMode.flag,
                 is_nip16=True,
                 is_nip33=True,
                 sort_direction=SortDirection.newest_first):

        StoreNIPSupport.__init__(self,
                                 delete_mode=delete_mode,
                                 nip16=is_nip16,
                                 nip33=is_nip33)

        self._sort_direction = sort_direction

        # by id
        self._events = {}
        # by kind/pubkey for replacable events if nip16
        self._replaceables = {}
        # by kind/pubkey/d_tag for para replacable events nip33
        self._para_replaceables = {}

    def add_event(self, evt: Event):
        c_evt: Event
        r_evt: Event

        if isinstance(evt, Event):
            evt = [evt]
        for c_evt in evt:
            if not self.is_ephemeral(c_evt):
                self._events[c_evt.id] = {
                    'is_deleted': False,
                    'evt': c_evt
                }

            if self.is_replaceable(c_evt):
                ukey = f'{c_evt.pub_key}:{c_evt.kind}'
                if ukey in self._replaceables:
                    r_evt = self._replaceables[ukey]
                    # actually removed no matter what delete mode
                    del self._events[r_evt.id]
                self._replaceables[ukey] = c_evt
            elif self.is_parameter_replaceable(c_evt):
                ukey = f'{c_evt.pub_key}:{c_evt.kind}:{c_evt.get_tag_value_pos("d", default="")}'
                if ukey in self._para_replaceables:
                    r_evt = self._para_replaceables[ukey]
                    # actually removed no matter what delete mode
                    del self._events[r_evt.id]
                self._para_replaceables[ukey] = c_evt

    def do_delete(self, evt: Event):
        if self._delete_mode == DeleteMode.no_action:
            return
        else:
            for c_id in evt.e_tags:
                if c_id in self._events:
                    if self._delete_mode == DeleteMode.flag:
                        self._events[c_id]['is_deleted'] = True
                    elif self._delete_mode == DeleteMode.delete:
                        # we just leave the is deleted flag in place but get rid of the evt data
                        # as it's just in memory it wouldn't be easy to get at anyway so really we're just freeing the mem
                        del self._events[c_id]['evt']

    def get_filter(self, filters):
        ret = set([])
        c_evt: Event
        limit = None
        # only been passed a single, put into list
        if isinstance(filters, dict):
            filters = [filters]

        # get limit if any TODO: add offset support
        for c_filter in filters:
            if 'limit' in c_filter:
                if limit is None or c_filter['limit'] > limit:
                    limit = c_filter['limit']

        # bit shit as we store unsorted we have to get all then sort and can only cut
        # to limit then
        for evt_id in self._events:
            r = self._events[evt_id]
            if not r['is_deleted']:
                c_evt = r['evt']
                for c_filter in filters:
                    if c_evt.test(c_filter):
                        ret.add(c_evt)

        def _updated_sort(evt_data):
            return evt_data['created_at']

        ret = [c_evt.data() for c_evt in ret]
        if self._sort_direction != SortDirection.natural:
            ret.sort(key=_updated_sort, reverse=self._sort_direction==SortDirection.newest_first)

        if limit is not None:
            ret = ret[:limit]

        return ret


class RelayMemoryEventStore(MemoryEventStore, RelayEventStoreInterface):
    pass