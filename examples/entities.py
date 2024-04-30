from monstr.entities import Entities

def show_entities():
    # nip19 encoded profile
    n_profile = 'nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gpp4mhxue69uhhytnc9e3k7mgpz4mhxue69uhkg6nzv9ejuumpv34kytnrdaksjlyr9p'

    # extract data
    decoded = Entities.decode(n_profile)
    print(decoded)

    # re-encode
    print(Entities.encode('nprofile', decoded))

if __name__ == "__main__":
    show_entities()