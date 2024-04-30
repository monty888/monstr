from monstr.entities import Entities

def test():
    # just test the examples from https://github.com/nostr-protocol/nips/blob/master/19.md

    # npub encode and decode
    assert Entities.decode('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg') == \
           '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e'
    assert Entities.encode('npub', '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e') == \
        'npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg'

    # nsec encode and decode
    assert Entities.decode('nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5') == \
           '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa'
    assert Entities.encode('nsec', '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa') == \
        'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5'

    # nprofile encode and decode
    nprofile_example = Entities.decode('nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p')

    assert nprofile_example['pubkey'] == '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d'

    assert 'wss://r.x.com' in nprofile_example['relay']
    assert 'wss://djbas.sadkb.com' in nprofile_example['relay']

    assert Entities.encode('nprofile', {
        'pubkey': '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d',
        'relay': ['wss://r.x.com','wss://djbas.sadkb.com']
    }) == 'nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p'


    # own examples to test

    nevent_example = Entities.decode('nevent1qqs2309gmw657ys52967enxsrh2syu54tjss42xjc829f5ty9g8j4gspzpmhxue69uhkummnw3ezuamfdejsygzxljlrqe027xh8sy2xtyjwfzfrxcll8afxh4hh847psjckhkxwf5psgqqqqqqs32mxmc')
    assert nevent_example['event_id'] == 'a8bca8dbb54f12145175ecccd01dd50272955ca10aa8d2c1d454d1642a0f2aa2'
    assert nevent_example['author'] == '46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184b16bd8ce4d'
    assert nevent_example['relay'] == 'wss://nostr.wine'
    assert nevent_example['kind'] == 1

    assert Entities.encode('nevent',{
        'event_id': 'a8bca8dbb54f12145175ecccd01dd50272955ca10aa8d2c1d454d1642a0f2aa2',
        'author': '46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184b16bd8ce4d',
        'relay': 'wss://nostr.wine',
        'kind': 1
    }) == 'nevent1qqs2309gmw657ys52967enxsrh2syu54tjss42xjc829f5ty9g8j4gspzpmhxue69uhkummnw3ezuamfdejsygzxljlrqe027xh8sy2xtyjwfzfrxcll8afxh4hh847psjckhkxwf5psgqqqqqqs32mxmc'


    naddr_example = Entities.decode('naddr1qq9rzd3h8y6nqwf5xyuqygzxljlrqe027xh8sy2xtyjwfzfrxcll8afxh4hh847psjckhkxwf5psgqqqw4rsty50fx')
    # assert naddr_example['id'] == '1679509418' ---CHECK THIS FIRST...
    assert naddr_example['author'] == '46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184b16bd8ce4d'
    assert naddr_example['kind'] == 30023

    assert Entities.encode('naddr', {
        'id': '1679509418',
        'author': '46fcbe3065eaf1ae7811465924e48923363ff3f526bd6f73d7c184b16bd8ce4d',
        'kind': 30023
    }) == 'naddr1qq9rzd3h8y6nqwf5xyuqygzxljlrqe027xh8sy2xtyjwfzfrxcll8afxh4hh847psjckhkxwf5psgqqqw4rsty50fx'


    # note encode and decode
    assert Entities.decode('note1g7vhs4fqs9rq4e0w8mpn0t8x907q8a4uauugrv75zhdl5knpddcsh2rcsv') == \
        '479978552081460ae5ee3ec337ace62bfc03f6bcef3881b3d415dbfa5a616b71'
    assert Entities.encode('note', '479978552081460ae5ee3ec337ace62bfc03f6bcef3881b3d415dbfa5a616b71') == \
           'note1g7vhs4fqs9rq4e0w8mpn0t8x907q8a4uauugrv75zhdl5knpddcsh2rcsv'


    print('all OK')


if __name__ == "__main__":
    test()