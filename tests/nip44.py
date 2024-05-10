import json
import os
from monstr.encrypt import Keys, NIP44Encrypt
from monstr.util import util_funcs
from monstr.signing import SignerInterface, BasicKeySigner
from monstr.event.event import Event
# from tests.nip4 import TEST_TEXTS

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
        assert my_enc._get_conversation_key(to_pub).hex() == conversation_key

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

        cacl_chacha_key, calc_chacha_nonce, calc_hmac_key = my_enc._get_message_key(conversion_key=conversation_key,
                                                                                    nonce=nonce)

        assert cacl_chacha_key == chacha_key
        assert calc_chacha_nonce == chacha_nonce
        assert calc_hmac_key == hmac_key

    def _test_do_encrypt_decrypt(the_test):
        sec1 = the_test['sec1']
        k1 = Keys(sec1)
        sec2 = the_test['sec2']
        k2 = Keys(sec2)
        nonce = bytes.fromhex(the_test['nonce'])
        conversation_key =the_test['conversation_key']
        plain_text = the_test['plaintext']
        payload = the_test['payload']

        my_enc = NIP44Encrypt(Keys(sec1))

        # test we get the same conversation key
        my_conv_k = my_enc._get_conversation_key(for_pub_k=k2.public_key_hex()).hex()
        print(f'expecting conversation key: {tail(conversation_key)} got {tail(my_conv_k)}')
        assert my_conv_k == conversation_key

        cacl_chacha_key, calc_chacha_nonce, calc_hmac_key = my_enc._get_message_key(
            conversion_key=bytes.fromhex(my_conv_k),
            nonce=nonce)

        padded = NIP44Encrypt._pad(plain_text)

        chacha_key, chacha_nonce, hmac_key = my_enc._get_message_key(conversion_key=bytes.fromhex(conversation_key),
                                                                     nonce=nonce)

        # test encrypts as expected...
        cipher_text = my_enc._do_encrypt(padded_data=padded,
                                         key=chacha_key,
                                         nonce=chacha_nonce)

        calc_payload = my_enc._make_payload(cipher_text=cipher_text,
                                            hmac_key=hmac_key,
                                            nonce=nonce,
                                            version=2)

        print(f'expected payload: {tail(payload)} got {tail(calc_payload)}')
        assert calc_payload == payload

        # now we check decrypting payload using k2 = plain text
        calc_plain_text = NIP44Encrypt(k2).decrypt(payload=calc_payload,
                                                   for_pub_k=k1.public_key_hex())

        print(f'expected plain_text: {tail(plain_text)} got {tail(calc_plain_text)}')
        assert calc_plain_text == plain_text

    def _test_get_invalid_conversation_key(the_test):
        success = False
        print(f'checking for: {the_test["note"]}')
        try:
            sec1 = the_test['sec1']
            k1 = Keys(sec1)
            pub = the_test['pub2']
            my_enc = NIP44Encrypt(Keys(sec1))
            my_enc._get_conversation_key(pub)
            # shouldn't get here....
            success = True
        except Exception as e:
            pass

        assert success is False

    def _test_invalid_decrypt(the_test):
        success = False
        print(f'checking for: {the_test["note"]}')
        try:
            con_key = bytes.fromhex(the_test['conversation_key'])
            nonce = bytes.fromhex(the_test['nonce'])
            plaintext = the_test['plaintext']
            payload = the_test['payload']
            nonce, ciper_text, mac = NIP44Encrypt._decode_payload(payload)


            chacha_key, chacha_nonce, hmac_key = NIP44Encrypt._get_message_key(conversion_key=con_key,
                                                                               nonce=nonce)

            calculated_mac = NIP44Encrypt._hmac_aad(key=hmac_key,
                                                    message=ciper_text,
                                                    aad=nonce,
                                                    hash_function=NIP44Encrypt.V2_HASH)

            if calculated_mac != mac:
                raise ValueError('invalid MAC')

            padded = NIP44Encrypt._do_decrypt(ciper_text=ciper_text,
                                              key=chacha_key,
                                              nonce=chacha_nonce)

            plain_text = NIP44Encrypt._unpad(padded=padded)

            # sec1 = the_test['sec1']
            # k1 = Keys(sec1)
            # pub = the_test['pub2']
            # my_enc = NIP44Encrypt(Keys(sec1))
            # my_enc._get_conversation_key(pub)
            # shouldn't get here....
            success = True
        except Exception as e:
            print(e)
            pass

        assert success is False


    def _do_valid_tests(test_json):
        print('** valid tests **')
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
            elif test_name == 'encrypt_decrypt':
                the_tests = test_json[test_name]
                print(f'doing encrypt_decrypt key tests')
                n_tests = len(the_tests)
                for tn in range(0, n_tests):
                    _test_do_encrypt_decrypt(the_tests[tn])

                    # _test_message_keys(the_tests[tn], conversation_key)
                    print(f'{tn + 1} of {n_tests} OK')
            else:
                print(f'no tests for {test_name}')

    def _do_invalid_tests(test_json):
        print('** invalid tests **')
        for test_name in test_json:
            if test_name == 'get_conversation_key':
                the_tests = test_json[test_name]
                print(f'doing conversation key tests')
                n_tests = len(the_tests)
                for tn in range(0, n_tests):
                    _test_get_invalid_conversation_key(the_tests[tn])
                    print(f'{tn + 1} of {n_tests} OK')
            elif test_name == 'decrypt':
                the_tests = test_json[test_name]
                print(f'doing decrypt tests')
                n_tests = len(the_tests)
                for tn in range(0, n_tests):
                    _test_invalid_decrypt(the_tests[tn])
                    print(f'{tn + 1} of {n_tests} OK')

            else:
                print(f'no tests for {test_name}')

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
                elif test_type == 'invalid':
                    _do_invalid_tests(nip44_tests[c_item][test_type])


    """ 
        extra test using Encrypter.encrypt_event and .decrypt_event util functions that
        that NIP44Encrypt
    """
    print('test event based')

    test_file = 'test_texts.json'
    with open(test_file, 'r') as f:
        test_texts = json.load(f)

    test_texts = test_texts['texts']
    count = len(test_texts)
    # rnd gen so keys
    enc_key = Keys()
    to_key = Keys()

    my_enc = NIP44Encrypt(enc_key)
    for i, c_text in enumerate(test_texts):

        enc_evt = my_enc.encrypt_event(evt=Event(content=c_text),
                                       to_pub_k=to_key.public_key_hex())

        dec_evt = my_enc.decrypt_event(enc_evt)

        # after enc/decode dec_evt.content should still == c_text
        assert dec_evt.content == c_text

        print(f'{i + 1} of {count} OK')


if __name__ == '__main__':
    # asyncio.run(nip44_encrypt_payload('some test'))
    test_file()

