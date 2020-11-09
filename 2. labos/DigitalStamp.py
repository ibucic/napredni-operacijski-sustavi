from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as a_padding

import DigitalEnvelope
import DigitalSignature
import Main


# Funkcija prima poruku koja se ispisuje, listu sa enkriptiranom porukom i ključem i hash funkciju
# Funkcija vraća izračunati sažetak poruke
def create_digest_stamp(pair, hashing_algorithm):
    # print('Izrađujem sažetak.')
    hasher = hashes.Hash(hashing_algorithm, default_backend())
    for one in pair:
        hasher.update(one)
    digest = hasher.finalize()
    # print('Sažetak: ')
    # print(digest)
    return digest


# Funkcija za stvaranje digitalnog pečata
# Prima javni ključ primatelja i privatni ključ pošiljatelja
def create_digital_stamp(public_key_receiver, private_key_sender):
    # print('\n- Digitalna omotnica -\n')

    encrypt_hash = DigitalEnvelope.get_encrypt_decrypt_hash()

    encrypted_message, symmetric_key = DigitalEnvelope.make_encrypted_message_key()
    encrypted_key = public_key_receiver.encrypt(symmetric_key,
                                                a_padding.OAEP(mgf=a_padding.MGF1(algorithm=encrypt_hash),
                                                               algorithm=encrypt_hash,
                                                               label=None))

    stm_enc_message = input('Ime datoteke u koju želite spremiti enkriptiranu poruku P: ')
    stm_enc_key = input('Ime datoteke u koju želite spremiti enkriptirani tajni ključ K: ')
    Main.save_files([stm_enc_message, stm_enc_key], [encrypted_message, encrypted_key])

    print()
    pair = [encrypted_message, encrypted_key]

    # print('\n- Digitalni potpis -\n')

    hashing_algorithm = DigitalSignature.get_hashing_algorithm()

    digest = create_digest_stamp(pair, hashing_algorithm)

    stamp = private_key_sender.sign(digest, a_padding.PSS(mgf=a_padding.MGF1(hashing_algorithm),
                                                          salt_length=a_padding.PSS.MAX_LENGTH),
                                    hashing_algorithm)

    # print('Digitalni pečat: ')
    # print(stamp)

    stm = input('Ime datoteke u koju želite spremiti digitalni pečat: ')
    Main.save_files([stm], [stamp])


# Funkcija za provjeru digitalnog pečata
# Prima privatni ključ primatelja i javni ključ pošiljatelja,
# enkriptiranu poruku, ključ, inicijalizacijski vektor i primljeni pečat
def verify_digital_stamp(private_key_receiver, public_key_sender, encrypted_message, encrypted_key, iv, received_stamp):
    # print('\n- Digitalna omotnica -\n')

    decrypt_hash = DigitalEnvelope.get_encrypt_decrypt_hash()

    decrypted_key = private_key_receiver.decrypt(encrypted_key,
                                                 a_padding.OAEP(mgf=a_padding.MGF1(algorithm=decrypt_hash),
                                                                algorithm=decrypt_hash,
                                                                label=None))
    decrypted_message = DigitalEnvelope.decrypt_message(decrypted_key, encrypted_message, iv)

    print('\nDekriptirana poruka: ')
    print('\t' + decrypted_message + '\n')

    pair = [encrypted_message, encrypted_key]

    # print('\n- Digitalni potpis -\n')

    hashing_algorithm = DigitalSignature.get_hashing_algorithm()

    digest = create_digest_stamp(pair, hashing_algorithm)

    try:
        public_key_sender.verify(received_stamp, digest, a_padding.PSS(mgf=a_padding.MGF1(hashing_algorithm),
                                                                       salt_length=a_padding.PSS.MAX_LENGTH),
                                 hashing_algorithm)
    except InvalidSignature:
        print('\nPečat nije valjan.')
    else:
        print('\nPečat je valjan.')
