import bech32
from monstr.encrypt import Keys


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
    def bytes_to_hex(data):
        return ''.join([hex(i).replace('0x', '').rjust(2, '0') for i in data])

    @staticmethod
    def encode(self):
        pass

    @staticmethod
    def decode(value: str):
        ret = {}
        if value.startswith('npub'):
            ret['pub_key'] = Keys.get_key(value).public_key_hex()
        elif value.startswith('nsec'):
            k = Keys.get_key(value)
            ret['pub_key'] = k.public_key_hex()
            ret['priv_key'] = k.private_key_hex()
        elif value.startswith('note'):
            ret['event_id'] = Keys.bech32_to_hex(value)
        elif value.startswith('nprofile'):


            as_int = bech32.bech32_decode(value)
            data = bech32.convertbits(as_int[1], 5, 8)
            print(parse_array(data, {
                0x00: {
                    'name': 'pubkey',
                    'format': Entities.bytes_to_hex
                },
                0x01: {
                    'name': 'relay'
                }
            }))


        return ret


def test():
    # just test the examples from https://github.com/nostr-protocol/nips/blob/master/19.md
    assert Entities.decode('npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg')['pub_key'] == \
           '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e'

    assert Entities.decode('nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5')['priv_key'] == \
           '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa'

    print(Entities.decode('nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p'))

    print('all OK')




if __name__ == "__main__":
    test()
