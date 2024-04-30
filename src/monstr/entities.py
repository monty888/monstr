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

