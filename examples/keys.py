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

    print(k)