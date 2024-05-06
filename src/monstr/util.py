from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from monstr.event.event import Event

import time
import sys
from datetime import datetime
import random
from hashlib import md5
import logging
import os
from pathlib import Path
from monstr.db.db import SQLiteDatabase

"""
    just a place to hand any util funcs that don't easily fit anywhere else
"""
class util_funcs:

    @staticmethod
    def ticks_as_date(ticks):
        return datetime.fromtimestamp(ticks)
    # reverse of above
    @staticmethod
    def date_as_ticks(dt: datetime):
        return int(dt.timestamp())

    @staticmethod
    def chunk(arr, chunk_size):
        if not hasattr(arr, '__iter__'):
            arr = [arr]

        if chunk_size is not None:
            ret = [arr[i:i + chunk_size] for i in range(0, len(arr), chunk_size)]
        else:
            ret = [arr]

        return ret

    @staticmethod
    def str_tails(the_str, taillen=4, spacer='...'):
        # returns str start...end chars for taillen
        ret = '?...?'

        if the_str:
            if len(the_str) < (taillen*2)+3:
                ret = the_str
            else:
                ret = (f'{the_str[:taillen]}'
                       f'{spacer}'
                       f'{the_str[len(the_str)-taillen:]}')
        return ret

    @staticmethod
    def create_work_dir(top_dir, sub_dir=None):
        def fix_path_str(the_str):
            return the_str.replace(os.path.sep + os.path.sep, os.path.sep)

        f = Path(top_dir)
        the_top_dir = Path(fix_path_str(os.path.sep.join(f.parts)))

        if not the_top_dir.is_dir():
            parent_dir = Path(os.path.sep.join(f.parts[:-1]).replace(os.path.sep + os.path.sep, os.path.sep))

            # we'll only create the top dir so if the containing dir does't exist then error
            if not parent_dir.is_dir():
                print('no such directory %s to create nostrpy work directory %s in ' % (parent_dir, the_top_dir))
                sys.exit(os.EX_CANTCREAT)

            # make the directory
            logging.info('util_funcs::create_work_dir: attempting to create %s' % the_top_dir)
            try:
                os.makedirs(the_top_dir)
            except PermissionError as pe:
                print('error trying to create work director %s - %s' % (parent_dir, pe))
                sys.exit(os.EX_CANTCREAT)

        # is there a sub dir, check it exists and create if not
        if sub_dir is not None:
            the_sub_dir = Path(fix_path_str(os.path.sep.join(f.parts)+ os.path.sep + sub_dir))
            if not the_sub_dir.is_dir():
                try:
                    os.makedirs(the_sub_dir)
                except PermissionError as pe:
                    print('error trying to create work sub director %s - %s' % (the_sub_dir, pe))
                    sys.exit(os.EX_CANTCREAT)




    @staticmethod
    def create_sqlite_store(db_file):
        from monstr.event.persist_sqlite import RelaySQLiteEventStore
        from monstr.ident.persist import SQLiteProfileStore
        from monstr.channels.persist import SQLiteSQLChannelStore
        from monstr.settings.persist import SQLiteSettingsStore
        my_events = RelaySQLiteEventStore(db_file)
        if not my_events.exists():
            my_events.create()
            my_profiles = SQLiteProfileStore(db_file)
            my_profiles.create()
            my_channels = SQLiteSQLChannelStore(db_file)
            my_channels.create()
            db = SQLiteDatabase(db_file)
            my_settings = SQLiteSettingsStore(db_file)
            my_settings.create()
            # should perform better for us i think, esp on backfill
            db.execute_sql('PRAGMA journal_mode = WAL;')

        return SQLiteDatabase(db_file)

    @staticmethod
    def retry_db_func(the_func, retry_count=None):
        """
            specifically for sqlite as during a write the whole db is locked we'll retry
            inserts ... explain this more.... this should mainly be a problem if access
            from somewhere else anyhow as we should be using the same db object to access
            that applies a python lock when doing writes...
        """
        is_done = False
        retry_n = 0
        while not is_done and (retry_count is None or retry_n < retry_count):
            try:
                the_func()
                is_done = True
            except Exception as de:
                # FIXME: we probably should give up eventually!
                if 'locked' in str(de):
                    logging.debug('PersistEventHandler::do_event db locked, waiting to retry - %s' % de)
                    retry_n += 1
                    wait_time = (1 * retry_n * retry_n)
                    if wait_time > 30:
                        wait_time = 30
                    time.sleep(wait_time)

                else:
                    is_done = True
                    print('shit needs fixing!!!!')
                    print(de)
                    sys.exit(0)

    @staticmethod
    def get_background_task(the_func, *args):
        """ get a function to run in Greenlet/Thread
        :param the_func:
        :param args:
        :return:
        """
        def task():
            the_func(*args)
        return task

    @staticmethod
    def get_rnd_hex_str(length: int = 4):

        """
        :return: creates a randomish hex str of length used for sub_ids where not given
        and by relay to generate challenge strs to be signed
        max length that'll be returned is 32chars
        """
        ret = str(random.randrange(1, 1000)) + str(time.time())
        ret = md5(ret.encode('utf8')).hexdigest()[:length]
        return ret

    @staticmethod
    def is_hex_part(hex: str, max_length: int = 64):
        """
            returns true if hex is only hex chars and is <= max_length
        """
        ret = False
        if len(hex) <= max_length:
            # and also hex, will throw otherwise
            try:
                bytearray.fromhex(hex)
                ret = True
            except:
                pass
        return ret


class NIPSupport:
    """
        is_NIPnn methods, all returning False,
        if store has support for nip it should override that isNIPnn method
    """

    def __init__(self,
                 nip09: bool = None,
                 nip16: bool = None,
                 nip22: bool = None,
                 nip33: bool = None,
                 nip40: bool = None,
                 nip42: bool = None):

        self._nip_support = {
            9: nip09,
            16: nip16,
            22: nip22,
            33: nip33,
            40: nip40,
            42: nip42
        }

        # as list format, assumed won't change while running
        self._nip_support_list = []
        for k,v in self._nip_support.items():
            if v is True:
                self._nip_support_list.append(k)
        self._nip_support_list.sort()

    @property
    def NIP09(self) -> bool:
        # event deletes https://github.com/nostr-protocol/nips/blob/master/09.md
        return self._nip_support[9]

    @property
    def NIP16(self) -> bool:
        # event treatment https://github.com/nostr-protocol/nips/blob/master/16.md
        return self._nip_support[16]

    @property
    def NIP22(self) -> bool:
        # parameter replacable events https://github.com/nostr-protocol/nips/blob/master/33.md
        return self._nip_support[22]

    @property
    def NIP33(self) -> bool:
        # parameter replacable events https://github.com/nostr-protocol/nips/blob/master/33.md
        return self._nip_support[33]

    @property
    def NIP40(self) -> bool:
        # Expiration Timestamp https://github.com/nostr-protocol/nips/blob/master/40.md
        return self._nip_support[40]

    @property
    def NIP42(self) -> bool:
        # Authentication of clients to relays https://github.com/nostr-protocol/nips/blob/master/42.md
        return self._nip_support[42]

    @property
    def supported_nips(self) -> list:
        return list(self._nip_support_list)


class ConfigError(Exception):
    pass
