class NostrCommandException(Exception):
    # exception raised that'll return command result as NIP-20
    # https://github.com/nostr-protocol/nips/blob/master/20.md

    def __init__(self, event_id: str, success: bool, message: str):
        self._event_id = event_id
        self._success = success
        self._message = message
        super().__init__('%s - %s' % (event_id, message))

    def get_data(self):
        # for transfer back to a client
        return ['OK', self._event_id, self._success, self._message]

    @classmethod
    def event_already_exists(cls, event_id):
        return NostrCommandException(event_id=event_id,
                                     success=True,
                                     message='duplicate: event already stored by relay')


class NostrNoticeException(Exception):
    # exception raised that just return a notice to the caller
    pass


class NostrNotAuthenticatedException(Exception):
    # raised on client trying to do something that requires authentication when it hasn't authed
    pass

