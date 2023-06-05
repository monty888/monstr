"""
    support for bech32 encoded entities
    https://github.com/nostr-protocol/nips/blob/master/19.md
"""

import bech32
from monstr.encrypt import Keys

class UnknownEntity(Exception):
    pass

# this code is ripped and edited from https://github.com/ustropo/uttlv
def parse_array(data, tag_map: dict = None) -> bool:
    # orifinally in class
    min_size = 1
    tag_size = 1
    endian = "big"

    def decode_len_size(data: bytes) -> int:
        if data[0] < 0x80:
            return 1
        return data[0] - 0x80 + 1



    ret = {}
    """Parse a byte array into a TLV object"""
    if isinstance(data, list):
        data = bytes(data)
    elif not isinstance(data, bytes):
        raise TypeError("Data must be bytes type.")
    # Check size
    if len(data) < min_size:
        raise AttributeError(f"Data must be at least {min_size} bytes long")
    # Start parsing
    aux = data
    while len(aux) > min_size:
        # Tag value
        tag = int.from_bytes(aux[: tag_size], byteorder=endian)
        # Len value
        aux = aux[tag_size:]
        len_size = decode_len_size(aux)
        offset = 0 if len_size == 1 else 1
        length = int.from_bytes(aux[offset:len_size], byteorder=endian)
        # Value
        aux = aux[len_size:]
        tag_value = aux[:length]
        # Next value
        aux = aux[length:]
        # Check if tag has any parser

        if tag_map is not None:
            tag_name = tag
            if tag in tag_map:
                tag_info = tag_map[tag]
                if 'name' in tag_info:
                    tag_name = tag_info['name']
                if 'format' in tag_info:
                    tag_value = tag_info['format'](tag_value)
            # tg_type = tag_map.get(TLV.Config.Type)
            # if tg_type is not None:
            #     # *Ideally* we would include this in ALLOWED_TYPES,
            #     # but this is the easiest way I can think of
            #     # to pass in the tag map config at the same time.
            #     if type(tg_type) is dict:
            #         value = NestedEncoder(tg_type).parse(value, self._new_equivalent_tlv())
            #     else:
            #         formatter = ALLOWED_TYPES.get(tg_type)
            #         if formatter is not None:
            #             value = formatter().parse(value, self._new_equivalent_tlv())
        # Set value
        # SH fix this shit
        if tag_name in ret:

            if not isinstance(ret[tag_name], list):
                ret[tag_name] = [ret[tag_name]]

            ret[tag_name].append(tag_value)
        else:
            ret[tag_name] = tag_value
    # Done parsing
    return ret


class Entities:

    @staticmethod
    def bech32_to_hex(key: str):
        # should be the reverese of hex_to_bech32...
        as_int = bech32.bech32_decode(key)
        data = bech32.convertbits(as_int[1], 5, 8)
        Entities.bytes_to_hex(data)

    @staticmethod
    def bytes_to_hex(data: bytes):
        return ''.join([hex(i).replace('0x', '').rjust(2, '0') for i in data])

    @staticmethod
    def bytes_to_str(data: bytes):
        return data.decode('utf8')

    @staticmethod
    def bytes_to_int(data: bytes):
        return int.from_bytes(data, byteorder='big')

    @staticmethod
    def make_int_arr(key, encode_str: str, format='hex'):
        if format == 'hex':
            ret = [int(encode_str[i:i + 2], 16) for i in range(0, len(encode_str), 2)]
        else:
            ret = [ord(e) for e in encode_str]

        ret = [key, len(ret)] + ret
        return ret

    # @staticmethod
    # def encode_field(key, prefix, data, format='hex'):
    #     if format == 'hex':
    #         as_int = [int(data[i:i + 2], 16) for i in range(0, len(data), 2)]
    #     else:
    #         as_int = data.encode('utf8')
    #
    #     as_int = [key, len(as_int)] + as_int
    #     data = bech32.convertbits(as_int, 8, 5)
    #     return bech32.bech32_encode(prefix, data)

    @staticmethod
    def encode(name: str, data: dict):
        if name in ('npub', 'nsec', 'note'):
            ret = Keys.hex_to_bech32(data, prefix=name)
        else:
            if name == 'nprofile':
                int_arr = Entities.make_int_arr(0, data['pubkey'])
            elif name == 'nevent':
                int_arr = Entities.make_int_arr(0, data['event_id'])
            elif name == 'nrelay':
                int_arr = Entities.make_int_arr(0, data['relay'], format='utf8')
            elif name == 'naddr':
                int_arr = Entities.make_int_arr(0, data['id'], format='utf8')
            else:
                raise UnknownEntity(name)

            if 'relay' in data and name in ('nprofile', 'nevent', 'naddr'):
                relays = data['relay']
                if isinstance(relays, str):
                    relays = [relays]

                for c_relay in relays:
                    int_arr += Entities.make_int_arr(1, c_relay, format='utf8')

            if 'author' in data and name in ('naddr', 'nevent'):
                int_arr += Entities.make_int_arr(2, data['author'])

            if 'kind' in data and name in ('naddr', 'nevent'):

                int_b = [int(i) for i in int.to_bytes(data['kind'], byteorder='big', length=4)]

                int_arr += [3, 4] + int_b

            # finally output as bech32
            data = bech32.convertbits(int_arr, 8, 5)
            ret = bech32.bech32_encode(name, data)

        return ret


    @staticmethod
    def decode(value: str):
        """
            npub, nsec, note are returned as str
            everything else returned as dict
            for npub, nsec and event note can just as easily use Keys.bech32 directly anyway
        """
        ret = None
        if value.startswith('npub') or value.startswith('nsec') or value.startswith('note'):
            ret = Keys.bech32_to_hex(value)
        elif value.startswith('nprofile'):

            as_int = bech32.bech32_decode(value)
            data = bech32.convertbits(as_int[1], 5, 8)
            ret = parse_array(data, {
                0x00: {
                    'name': 'pubkey',
                    'format': Entities.bytes_to_hex
                },
                0x01: {
                    'name': 'relay',
                    'format': Entities.bytes_to_str
                }
            })

        elif value.startswith('nevent'):
            as_int = bech32.bech32_decode(value)
            data = bech32.convertbits(as_int[1], 5, 8)
            ret = parse_array(data, {
                0x00: {
                    'name': 'event_id',
                    'format': Entities.bytes_to_hex
                },
                0x01: {
                    'name': 'relay',
                    'format': Entities.bytes_to_str
                },
                0x2: {
                    'name': 'author',
                    'format': Entities.bytes_to_hex
                },
                0x3: {
                    'name': 'kind',
                    'format': Entities.bytes_to_int
                }
            })

        elif value.startswith('nrelay'):
            as_int = bech32.bech32_decode(value)
            data = bech32.convertbits(as_int[1], 5, 8)
            ret = parse_array(data, {
                0x00: {
                    'name': 'relay',
                    'format': Entities.bytes_to_str
                }
            })

        elif value.startswith('naddr'):
            as_int = bech32.bech32_decode(value)
            data = bech32.convertbits(as_int[1], 5, 8)
            ret = parse_array(data, {
                0x00: {
                    'name': 'id',
                    'format': Entities.bytes_to_str
                },
                0x2: {
                    'name': 'author',
                    'format': Entities.bytes_to_hex
                },
                0x3: {
                    'name': 'kind',
                    'format': Entities.bytes_to_int
                }
            })

        return ret


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
