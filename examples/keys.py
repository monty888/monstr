"""
    create keys or show keys in the hex/npub/npriv formats

    with no args creates a new key pair and outputs npriv/hex npub/hex of the generated key
    with npriv same as above for that key
    with npub just the npub/hex
    with hex npub/hex for that hex
    with hex and 'private'  npriv/hex npub/hex

"""
import sys
from monstr.encrypt import Keys

if __name__ == "__main__":
    args = sys.argv[1:]
    if args:
        if len(args) > 1:
            k = Keys(priv_k=args[0])
        else:
            the_key: str = args[0]
            if the_key.startswith('nsec'):
                k = Keys(priv_k=the_key)
            else:
                k = Keys(pub_k=the_key)


    else:
        k = Keys()

    if k.private_key_hex():
        print('**private**')
        print('%s%s' % ('hex'.ljust(10),
                        k.private_key_hex()))
        print('%s%s' % ('bech32'.ljust(10),
                        k.private_key_bech32()))
    print('**public**')
    print('%s%s' % ('hex'.ljust(10),
                    k.public_key_hex()))
    print('%s%s' % ('bech32'.ljust(10),
                    k.public_key_bech32()))


    print(k.is_hex_key('5c4bf3e548683d61fb72be5f48c2dff0cf51901b9dd98ee8db178efe522e325f'))