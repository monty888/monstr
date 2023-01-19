
class NostrCommandException(Exception):

    @classmethod
    def event_already_exists(cls, id):
        return NostrCommandException('event already exists %s' % id)


class ConfigurationError(Exception):
    # unhappy about something we receive from the command line
    pass