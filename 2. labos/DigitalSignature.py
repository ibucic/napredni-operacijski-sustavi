from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import Main


# Funkcija služi za odabir hash funkcije za izračunavanje sažetka poruke, te vraća odabranu hash funkciju
def get_hashing_algorithm():
    print('Odaberite algoritam za RSA enkripciju: a) SHA-2\tb) SHA-3')
    alg = input('[a/b]? : ')
    if alg == 'a':
        print('Odaberite veličinu za SHA-2: a) SHA-256\tb) SHA-512')
        size = input('[a/b]? : ')
        hashing_algorithm = hashes.SHA256() if size == 'a' else hashes.SHA512()
    else:
        print('Odaberite veličinu za SHA-3: a) SHA3-256\tb) SHA3-512')
        size = input('[a/b]? : ')
        hashing_algorithm = hashes.SHA3_256() if size == 'a' else hashes.SHA3_512()
    return hashing_algorithm


# Funkcija prima poruku koja se ispisuje za korisnika koji unosi poruku čiji sažetak želi i hash funkciju
# Funkcija vraća izračunati sažetak poruke
def create_digest(message, hashing_algorithm):
    hasher = hashes.Hash(hashing_algorithm, default_backend())
    hasher.update(message.encode())
    digest = hasher.finalize()
    # print('Sažetak: ')
    # print(digest)
    return digest


# Funkcija za stvaranje digitalnog potpisa
# Prima privatni ključ pošiljatelja
def create_signature(private_key):
    print('\n- Stvaramo svojim privatnim ključem -\n')

    hashing_algorithm = get_hashing_algorithm()

    input_message = input('Ispišite poruku čiji sažetak želite: ')
    message_name = input('Ime datoteke u koju želite spremiti poruku: ')
    with open(message_name, 'w') as file:
        file.write(input_message)
    digest = create_digest(input_message, hashing_algorithm)

    signature = private_key.sign(digest, padding.PSS(mgf=padding.MGF1(hashing_algorithm),
                                                     salt_length=padding.PSS.MAX_LENGTH),
                                 hashing_algorithm)

    # print('Digitalni potpis:')
    # print(signature)

    sign = input('Ime datoteke u koju želite spremiti digitalni potpis: ')
    Main.save_files([sign], [signature])


# Funkcija za provjeru digitalnog potpisa
# Prima javni ključ pošiljatelja, primljenu poruku i primljeni potpis
def verify_signature(public_key, received_message, received_signature):
    print('\n- Provjeravamo javnim ključem -\n')

    hashing_algorithm = get_hashing_algorithm()

    digest = create_digest(received_message, hashing_algorithm)

    try:
        public_key.verify(received_signature, digest, padding.PSS(mgf=padding.MGF1(hashing_algorithm),
                                                                  salt_length=padding.PSS.MAX_LENGTH),
                          hashing_algorithm)
    except InvalidSignature:
        print('\nPotpis nije valjan.')
    else:
        print('\nPotpis je valjan.')
