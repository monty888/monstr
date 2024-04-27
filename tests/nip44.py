import json
import os
from monstr.encrypt import Keys, NIP44Encrypt
from monstr.util import util_funcs
from monstr.signing import SignerInterface, BasicKeySigner

tail = util_funcs.str_tails

async def nip44_encrypt_payload(payload: str, version=2):
    # testing for ...., then make use test case file
    # "sec1": "315e59ff51cb9209768cf7da80791ddcaae56ac9775eb25b6dee1234bc5d2268",
    # "pub2": "c2f9d9948dc8c7c38321e4b85c8558872eafa0641cd269db76848a6073e69133",
    # "conversation_key": "3dfef0ce2a4d80a25e7a328accf73448ef67096f65f79588e358d9a0eb9013f1"

    priv_k = 'df2f560e213ca5fb33b9ecde771c7c0cbd30f1cf43c2c24de54480069d9ab0af'
    pub_k= 'eeea26e552fc8b5e377acaa03e47daa2d7b0c787fac1e0774c9504d9094c430e'

    k = Keys(priv_k=priv_k)
    my_sign:SignerInterface = BasicKeySigner(key=k)



    # get_conversion_key(priv_k=priv_k, to_pub_k=pub_k)
    test_msg = 'SOME TEST TEXT!!!'


    payload = await my_sign.nip44_encrypt(plain_text=test_msg,
                                             to_pub_k=pub_k)

    print(f'nip44 payload: {payload}')

    plain_text = await my_sign.nip44_decrypt(payload=payload,
                                             for_pub_k=pub_k)

    print(f'nip44 plain text: {plain_text}')

    payload = await my_sign.nip4_encrypt(plain_text=plain_text,
                                         to_pub_k=pub_k)

    print(f'nip 4 payload: {payload}')

    plain_text = await my_sign.nip4_decrypt(payload=payload,
                                            for_pub_k=pub_k)

    print(f'nip4 plain text: {plain_text}')


def test_file():
    """
        runs through some basic tests against the values we should as from test vectors file
        from https://github.com/paulmillr/nip44/blob/main/nip44.vectors.json
    """
    cwd = os.getcwd()

    f_name = 'nip44.vectors.json'

    if cwd.endswith('/tests'):
        test_file = f'{cwd}/{f_name}'
    else:
        test_file = f'./tests/{f_name}'

    print(test_file)

    def _test_conversation_key(the_test):
        sec = the_test['sec1']
        to_pub = the_test['pub2']
        conversation_key = the_test['conversation_key']
        print(f'sec: {tail(sec)} - pub: {tail(to_pub)} expected conversation key: {tail(conversation_key)}')

        my_enc = NIP44Encrypt(sec)
        assert my_enc._nip44_get_conversion_key(to_pub).hex() == conversation_key

    def _test_message_keys(the_test, conversation_key):
        nonce = bytes.fromhex(the_test['nonce'])
        chacha_key = bytes.fromhex(the_test['chacha_key'])
        chacha_nonce = bytes.fromhex(the_test['chacha_nonce'])
        hmac_key = bytes.fromhex(the_test['hmac_key'])

        print(f'nonce: {tail(nonce.hex())} expected '
              f'chacha key: {tail(chacha_key.hex())} '
              f'chacha nonce: {tail(chacha_nonce.hex())} '
              f'hmac key: {tail(hmac_key.hex())}')

        # random keys - it doesn't actually matter what they are
        my_enc = NIP44Encrypt(Keys())

        cacl_chacha_key, calc_chacha_nonce, calc_hmac_key = my_enc._nip44_get_message_key(conversion_key=conversation_key,
                                                                                          nonce=nonce)

        assert cacl_chacha_key == chacha_key
        assert calc_chacha_nonce == chacha_nonce
        assert calc_hmac_key == hmac_key

        # my_enc = NIP44Encrypt(sec)
        # assert my_enc._nip44_get_conversion_key(to_pub).hex() == conversation_key


    def _do_valid_tests(test_json):
        for test_name in test_json:
            if test_name == 'get_conversation_key':
                the_tests = test_json[test_name]
                print(f'doing conversation key tests')
                n_tests = len(the_tests)
                for tn in range(0, n_tests):
                    _test_conversation_key(the_tests[tn])
                    print(f'{tn+1} of {n_tests} OK')
            elif test_name == 'get_message_keys':
                the_tests = test_json[test_name]['keys']
                conversation_key = bytes.fromhex(test_json[test_name]['conversation_key'])
                print(f'doing message key tests using conversation key: {tail(conversation_key.hex())}')
                n_tests = len(the_tests)
                for tn in range(0, n_tests):
                    _test_message_keys(the_tests[tn], conversation_key)
                    print(f'{tn + 1} of {n_tests} OK')

    """
        open the file, we interested in the v2/valid and v2/invalid sections
        tests include methods that would never be called externally as they're intermediate steps 
    """
    test_file = 'nip44.vectors.json'
    with open(test_file, 'r') as f:
        nip44_tests = json.load(f)
    for c_item in nip44_tests:
        if c_item == 'v2':
            for test_type in nip44_tests[c_item]:
                if test_type == 'valid':
                    _do_valid_tests(nip44_tests[c_item][test_type])

if __name__ == '__main__':
    # asyncio.run(make_nip44_event())
    test_file()

