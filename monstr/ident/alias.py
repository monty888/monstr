import logging
from monstr.ident.profile import Profile
from monstr.ident.persist import MemoryProfileStore
from monstr.encrypt import Keys


class ProfileFileAlias:
    """
        in a file contains mappings between human usable alias and key pairs
        so we don't always have to type out full keys
    """
    def __init__(self, file_name: str):
        self._file_name = file_name
        self._store = MemoryProfileStore()
        try:
            self._store.import_file(self._file_name)
        except FileNotFoundError as fe:
            logging.info('FileProfiles::__init__ file doesn\'t exist yet - %s' % self._file_name)

    def get_profile(self, profile_name: str) -> Profile:
        ret = None
        matches = self._store.select_profiles(filter={
            'profile_name': profile_name
        })
        if matches:
            # first match
            ret = matches[0]
            # prefer a exact match if found
            c_p: Profile
            for c_p in matches:
                if c_p.profile_name == profile_name:
                    ret = c_p
                    break

        return ret

    def new_profile(self, profile_name:str,
                    keys:str = None,
                    auto_save: bool = True) -> Profile:

        if keys is not None:
            keys = Keys.get_key(keys)

        ret: Profile = self._store.new_profile(profile_name=profile_name,
                                               keys=keys)
        if auto_save:
            self.save()

        return ret

    def link_profile(self, profile_name:str,
                     keys: str,
                     auto_save=True) -> Profile:
        ret: Profile = self.get_profile(profile_name)

        if ret is None:
            raise Exception('profile not found: %s' % profile_name)

        new_keys = Keys.get_key(keys)
        if new_keys is None:
            raise Exception('keys don\'t look correct: %s' % keys)

        self._store.delete_profile(ret.keys)
        ret.keys = new_keys
        self._store.put_profile(ret)

        if auto_save:
            self.save()

        return ret

    def put_profile(self, profile: Profile):
        self._store.put_profile(profile,
                                is_local=True)

    def save(self):
        self._store.export_file(self._file_name)