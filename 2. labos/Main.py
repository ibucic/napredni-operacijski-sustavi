from os import path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_public_key

import DigitalEnvelope
import DigitalSignature
import DigitalStamp


# Funkcija prima listu imena datoteka i listu sadržaja datoteka,
# te sprema sadržaj u datoteku imena odabranog od korisnika.
def save_files(file_names, files):
    for file_name, data in zip(file_names, files):
        with open(file_name, 'wb') as file:
            file.write(data)


# Funkcija prima listu imena datoteka te čita sadržaj svake od datoteka, te vraća listu sadržaja traženih datoteka
# Funkcija se poziva poslije provjere postojanosti datoteka pa ova funkcija nema potrebe za tom provjerom.
def read_files(file_names):
    files = []
    for file_name in file_names:
        with open(file_name, 'rb') as file:
            file_content = file.read()
        files.append(file_content)
    return files


# Funkcija prima ključ i tip ključa (privatni ili javni) te po mogućnosti varijablu 'number'.
# Ako se funkciji pošalje varijabla 'number', funkcija ispisuje drugačiji tekst za upis naziva ključa
def save_file_keys(key, key_type, number=0):
    if number == 0:
        file_name = input('Ime datoteke spremljenog ključa - ' + key_type + ': ')
        with open(file_name, 'wb') as file:
            file.write(key)
    else:
        file_name = input('Ime datoteke spremljenog ključa - ' + key_type + ' broj ' + str(number) + ': ')
        with open(file_name, 'wb') as file:
            file.write(key)


# Funkcija prima ime ključa i tip ključa.
# S obzirom na tip ključa (privatni ili javni), funkcija čita iz datoteke i vraća traženi ključ
def read_key(key_name, key_type):
    if key_type == 'private':
        with open(key_name, 'rb') as file:
            key_bytes = file.read()
        private_key = load_pem_private_key(key_bytes, None, default_backend())
        return private_key
    elif key_type == 'public':
        with open(key_name, 'rb') as file:
            key_bytes = file.read()
        public_key = load_ssh_public_key(key_bytes, default_backend())
        return public_key


# Funkcija prima imena oba ključa (privatni i javni), čita i vraća oba ključa
# P.S. - Funkcija nije korištena u programu, ali je ostavljena čisto radi prikaza
def read_file_keys(private_key_name, public_key_name):
    with open(private_key_name, 'rb') as file:
        key_bytes = file.read()
    private_key = load_pem_private_key(key_bytes, None, default_backend())
    with open(public_key_name, 'rb') as file:
        key_bytes = file.read()
    public_key = load_ssh_public_key(key_bytes, default_backend())
    return private_key, public_key


# Funkcija prima listu duljine ključeva [1024, 2048, 3072], te proizvoljne varijable 'pair' i 'number'
# Funkcija vraća duljinu ključa/ključeva ovisno o broju parova ključeva koji se stvaraju
def RSA_length(keys_length, pair=None, number=1):
    if number == 1:
        print('Odaberite duljinu RSA ključa: 1) 1024\t2) 2048\t3) 3072')
        key_input = input('[1/2/3]? : ')
        key_length = keys_length[int(key_input) - 1]
        return key_length
    elif number == 2:
        key_lengths = []
        for unit in pair:
            print('Odaberite duljinu za ' + unit + ' RSA ključa: 1) 1024\t2) 2048\t3) 3072')
            key_input = input('[1/2/3]? : ')
            key_length = keys_length[int(key_input) - 1]
            key_lengths.append(key_length)
        return key_lengths[0], key_lengths[1]


# funkcija prima generirani par ključeva (privatni i javni), te proizvoljnu varijablu 'number'
# Funkcija vraća par stvorenih ključeva
def create_pair_keys(private_key, public_key, number=0):
    if number == 0:
        pr0_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
        save_file_keys(pr0_key, 'PRIVATNI KLJUČ')

        pu0_key = public_key.public_bytes(encoding=serialization.Encoding.OpenSSH,
                                          format=serialization.PublicFormat.OpenSSH)
        save_file_keys(pu0_key, 'JAVNI KLJUČ')

        pr_key = load_pem_private_key(pr0_key, None, default_backend())
        pu_key = load_ssh_public_key(pu0_key, default_backend())
        return pr_key, pu_key
    else:
        pr1_key = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
        save_file_keys(pr1_key, 'PRIVATNI KLJUČ', number)

        pu1_key = public_key.public_bytes(encoding=serialization.Encoding.OpenSSH,
                                          format=serialization.PublicFormat.OpenSSH)
        save_file_keys(pu1_key, 'JAVNI KLJUČ', number)

        pr_key = load_pem_private_key(pr1_key, None, default_backend())
        pu_key = load_ssh_public_key(pu1_key, default_backend())
        return pr_key, pu_key


# Funcija prima broj parova ključeva za stvoranje, a za potrebe ovog labosa, funcija može primiti samo brojeve 1 i 2
# Funkcija vraća par ili parove stvorenih ključeva
def keys_generator(number):
    print('Generiramo nove ključeve.')
    keys_length = [1024, 2048, 3072]

    if number == 1:
        key_length = RSA_length(keys_length)

        # Generiranje parova (private_key, public_key) ključeva
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_length, backend=default_backend())
        public_key = private_key.public_key()

        priv_key, publ_key = create_pair_keys(private_key, public_key)
        return priv_key, publ_key

    elif number == 2:
        key_length1, key_length2 = RSA_length(keys_length, pair=['prvi par', 'drugi par'], number=2)

        # Generiranje parova (private_key, public_key) ključeva
        private_key1 = rsa.generate_private_key(public_exponent=65537, key_size=key_length1, backend=default_backend())
        public_key1 = private_key1.public_key()

        private_key2 = rsa.generate_private_key(public_exponent=65537, key_size=key_length2, backend=default_backend())
        public_key2 = private_key2.public_key()

        priv_key1, publ_key1 = create_pair_keys(private_key1, public_key1, 1)
        priv_key2, publ_key2 = create_pair_keys(private_key2, public_key2, 2)
        return priv_key1, publ_key1, priv_key2, publ_key2

    print('\nKljučevi su spremljeni i spremni za korištenje.')


# Funcija prima dva stringa, tip ključa i tip korisnika i s obzirom na ulaz, čita potrebnu datoteku i vraća ključ
# key_type = ['private', 'public'], user_type = ['sender', 'receiver']
def check_return_key(key_type, user_type):
    keys = ['privatni ključ', 'javni ključ']
    users = ['pošiljatelja', 'primatelja']
    key_string = keys[0] if key_type == 'private' else keys[1]
    user_string = users[0] if user_type == 'sender' else users[1]
    while True:
        pu_key = input('Upišite naziv datoteke za ' + key_string + ' ' + user_string + ': ')
        if path.exists(pu_key):
            key = read_key(pu_key, key_type)
            return key
        else:
            print('Ne postoji nevedena datoteka. Upišite ime datoteke ponovno.')


# Funkcija prima akciju koju korisnik želi raditi (omotnica, potpis ili pečat), te što želi raditi sa tom akcijom
# Korisnik ima mogućnost kod stvaranja koristiti već stvorene ključeve ili može generirati novi par ključeva
# Funkcija vraća potrebne ključeve u ovisnosti o onome što korisnik želi raditi
def return_keys(action, subaction):
    if subaction == 'A':
        print('Želite li koristiti već stvoreni par/parove ključeva?')
        keys = input('[D/N]? : ')
    else:   # elif subaction == 'B'
        keys = 'D'
    # DIGITALNA OMOTNICA
    if action == 'A':
        if subaction == 'A':
            # enkripcija digitalne omotnice - vrati javni ključ primatelja
            if keys == 'D':
                publ_key = check_return_key('public', 'receiver')
                return publ_key
            elif keys == 'N':
                priv_key, publ_key = keys_generator(number=1)
                return publ_key
        elif subaction == 'B':
            # dekripcija digitalne omotnice - vrati privatni ključ primatelja
            if keys == 'D':
                priv_key = check_return_key('private', 'receiver')
                return priv_key
    # DIGITALNI POTPIS
    elif action == 'B':
        if subaction == 'A':
            # stvaranje digitalnog potpisa - vrati privatni ključ pošiljatelja
            if keys == 'D':
                priv_key = check_return_key('private', 'sender')
                return priv_key
            elif keys == 'N':
                priv_key, publ_key = keys_generator(number=1)
                return priv_key
        elif subaction == 'B':
            # provjera digitalnog potpisa - vrati javni ključ pošiljatelja
            if keys == 'D':
                publ_key = check_return_key('public', 'sender')
                return publ_key
    elif action == 'C':
        if subaction == 'A':
            # stvaranje digitalnog pečata - vrati javni ključ primatelja i privatni ključ pošiljatelja
            if keys == 'D':
                publ_key = check_return_key('public', 'receiver')
                priv_key = check_return_key('private', 'sender')
                return publ_key, priv_key
            elif keys == 'N':
                priv_key1, publ_key1, priv_key2, publ_key2 = keys_generator(number=2)
                return publ_key2, priv_key1
        elif subaction == 'B':
            # provjera digitalnog pečata - vrati privatni ključ primatelja i javni ključ pošiljatelja
            if keys == 'D':
                priv_key = check_return_key('private', 'receiver')
                publ_key = check_return_key('public', 'sender')
                return priv_key, publ_key


# Main program u kojem se pokreće cijeli labos i u kojem se odabire što se želi raditi u programu
if __name__ == '__main__':
    print('Odaberite jednu od 3 ponuđene opcije:\nA) DIGITALNA OMOTNICA\nB) DIGITALNI POTPIS\nC) DIGITALNI PEČAT')
    choice = input('[A/B/C]? : ')

    # DIGITALNA OMOTNICA
    if choice == 'A':
        print('\nDIGITALNA OMOTNICA\n')
        print('Što želite raditi sa digitalnom omotnicom: A) Enkripciju\tB) Dekripciju')
        ch_A = input('[A/B]? : ')
        if ch_A == 'A':
            public_key_main = return_keys(choice, ch_A)
            print('\nENKRIPCIJA DIGITALNE OMOTNICE')
            DigitalEnvelope.encrypt_digital_envelope(public_key_main)
        elif ch_A == 'B':
            private_key_main = return_keys(choice, ch_A)
            print('\nUnesite nazive datoteka primljenih porukom od pošiljatelja:')
            while True:
                env_enc_message = input('Kriptirana poruka P: ')
                env_enc_key = input('Kriptirani ključ K: ')
                iv = input('Inicijalizacijski vektor: ')
                if path.exists(env_enc_message) and path.exists(env_enc_key) and path.exists(iv):
                    print('\nDEKRIPCIJA DIGITALNE OMOTNICE')
                    read_f = read_files([env_enc_message, env_enc_key, iv])
                    envelope_encrypted_message, envelope_encrypted_key, envelope_iv = read_f[0], read_f[1], read_f[2]
                    DigitalEnvelope.decrypt_digital_envelope(private_key_main, envelope_encrypted_message,
                                                             envelope_encrypted_key, envelope_iv)
                    break
                else:
                    print('Ne postoje neke ili sve navedene datoteke. Unesite nazive datoteka ponovno.')

    # DIGITALNI POTPIS
    elif choice == 'B':
        print('\nDIGITALNI POTPIS\n')
        print('Što želite raditi sa digitalnim potpisom: A) Stvaranje\tB) Provjeru')
        ch_B = input('[A/B]? : ')
        if ch_B == 'A':
            private_key_main = return_keys(choice, ch_B)
            print('\nSTVARANJE DIGITALNOG POTPISA')
            DigitalSignature.create_signature(private_key_main)
        elif ch_B == 'B':
            public_key_main = return_keys(choice, ch_B)
            print('\nUnesite naziv datoteke primljene porukom od pošiljatelja.')
            while True:
                mess = input('Primljena poruka: ')
                sign = input('Primljen digitalni potpis: ')
                if path.exists(mess) and path.exists(sign):
                    print('\nPROVJERA DIGITALNOG POTPISA')
                    with open(mess, 'r') as message_file:
                        received_message = message_file.read()
                    read_f = read_files([sign])
                    signature = read_f[0]
                    DigitalSignature.verify_signature(public_key_main, received_message, signature)
                    break
                else:
                    print('Ne postoji navedena datoteka. Unesite naziv potpisa ponovno.')

    # DIGITALNI PEČAT
    elif choice == 'C':
        print('\nDIGITALNI PEČAT\n')
        print('Što želite raditi sa digitalnim pečatom: A) Stvaranje\tB) Provjeru')
        ch_C = input('[A/B]? : ')
        if ch_C == 'A':
            public_key2_main, private_key1_main = return_keys(choice, ch_C)
            print('\nSTVARANJE DIGITALNOG PEČATA')
            DigitalStamp.create_digital_stamp(public_key2_main, private_key1_main)
        elif ch_C == 'B':
            private_key2_main, public_key1_main = return_keys(choice, ch_C)
            print('\nUnesite nazive datoteka primljene porukom od pošiljatelja:')
            while True:
                stamp_enc_message = input('Kriptirana poruka P: ')
                stamp_enc_key = input('Kriptirani ključ K: ')
                iv = input('Inicijalizacijski vektor: ')
                s = input('Primljen digitalni pečat: ')
                if path.exists(stamp_enc_message) and path.exists(stamp_enc_key) and path.exists(iv) and path.exists(s):
                    print('\nPROVJERA DIGITALNOG PEČATA')
                    f = read_files([stamp_enc_message, stamp_enc_key, iv, s])
                    stamp_encrypted_message, stamp_encrypted_key, stamp_iv, stamp = f[0], f[1], f[2], f[3]
                    DigitalStamp.verify_digital_stamp(private_key2_main, public_key1_main, stamp_encrypted_message,
                                                      stamp_encrypted_key, stamp_iv, stamp)
                    break
                else:
                    print('Ne postoje neke ili sve navedene datoteke. Unesite nazive datoteka ponovno.')
