import json
from monstr.encrypt import NIP4Encrypt, Keys
from monstr.event.event import Event


def test_encrypt_decrypt():
    """
        very basic check that the nip4 encryption and decryption is working,
        better to have some standard test vectors like nip44
    """

    print('testing encrypt decrypts')

    # load some test texts
    test_file = 'test_texts.json'
    with open(test_file, 'r') as f:
        test_texts = json.load(f)
    test_texts = test_texts['texts']
    count = len(test_texts)

    # rnd gen so keys
    enc_key = Keys()
    to_key = Keys()

    my_enc = NIP4Encrypt(enc_key)

    # test the text based enc/dec
    print('test content based')
    for i, c_text in enumerate(test_texts):
        payload = my_enc.encrypt(c_text, to_key.public_key_hex())
        plain_text = my_enc.decrypt(payload, to_key.public_key_hex())

        # after enc/decode plaintext should still == c_text
        assert plain_text == c_text

        print(f'{i+1} of {count} OK')

    # test the slightly higher level fucs that do enc/dec with nostr events
    print('test event based')
    for i, c_text in enumerate(test_texts):

        enc_evt = my_enc.encrypt_event(evt=Event(content=c_text),
                                       to_pub_k=to_key.public_key_hex())
        dec_evt = my_enc.decrypt_event(enc_evt)

        # after enc/decode dec_evt.content should still == c_text
        assert dec_evt.content == c_text

        print(f'{i + 1} of {count} OK')


if __name__ == '__main__':
    # asyncio.run(nip44_encrypt_payload('some test'))
    test_encrypt_decrypt()