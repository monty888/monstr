from monstr.event.event import Event
from monstr.encrypt import Keys

def test():
    k = Keys()
    # event with no pow
    evt = Event(content='pow event',
                pub_key=k.public_key_hex(),
                kind=Event.KIND_TEXT_NOTE)

    # should be False even if we got lucky with event id as no target tags
    assert evt.nip13_valid_pow(0) is False
    print('Event with no pow failed valid pow 0 OK')

    # add pow to the event
    evt.add_pow(target=16)

    # event should nnow pass
    assert evt.nip13_valid_pow(16) is True
    print('Event valid pow 16 OK')

    # it shouldn't pass this as target was 16 event if it got lucky
    assert evt.nip13_valid_pow(18) is False
    print('Event target pow not valid 16 for 18 OK')

    # fake the tags - this should now fail as id will be reset, unlikely we do this in reality
    # if we got an event with faked tags from untrusted we'd expected to validate the event itself
    # first before checking any pow on the evnt
    evt.tags = [['nonce', '9999', '48']]
    assert evt.nip13_valid_pow(32) is False
    print('Event faked pow tags not valid OK')

    print('all OK')


if __name__ == "__main__":
    test()