import asyncio
import json
from monstr.giftwrap import GiftWrap
from monstr.encrypt import Keys
from monstr.signing import BasicKeySigner
from monstr.event.event import Event

async def test_encrypt_decrypt():
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

    # create rnd src dest keys wrappers
    send_k = Keys()
    rec_k = Keys()

    send_gift = GiftWrap(BasicKeySigner(send_k))
    rec_gift = GiftWrap(BasicKeySigner(rec_k))


    # test the text based enc/dec
    print('test content based')
    for i, c_text in enumerate(test_texts):
        test_event = Event(kind=1,
                           content=c_text)

        # make a wrapped event
        wrapped_evt, _ = await send_gift.wrap(test_event, rec_k)

        # assert that the reciever can unwrap it, and text is still as expected
        rumor_evt = await rec_gift.unwrap(wrapped_evt)

        assert rumor_evt.content == c_text
        print(f' {i + 1}.1 receiver decrypt OK')

        # also assert that we can't unwrap it (you'd need to keep and unwrap copy and link or something depending on app)
        decrypted = False
        try:
            # we'll fake the p_tags to force giftwrap to try and decrypt
            wrapped_evt.tags = [['p', send_k.public_key_hex()]]
            rumor_evt = await send_gift.unwrap(wrapped_evt)
            # shouldn't get here!
            decrypted = True
        except Exception as e:
            pass

        assert decrypted is False
        print(f' {i + 1}.2 sender no decrypt OK')




if __name__ == '__main__':
    # asyncio.run(nip44_encrypt_payload('some test'))
    asyncio.run(test_encrypt_decrypt())