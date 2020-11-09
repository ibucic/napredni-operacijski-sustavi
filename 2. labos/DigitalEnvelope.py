import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as a_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import Main


# Funcija prima šifru i veličinu bloka
# Funkcija omogućuje korisniku upisati poruku koju funkcija vraća kao enkriptiranu poruku
def encrypt_message(cipher, block_len):
    message1 = input('Napišite poruku koju želiš enkriptirati: ')
    padder = padding.PKCS7(block_len).padder()
    message = padder.update(message1.encode()) + padder.finalize()
    encrypted_message = cipher.encryptor().update(message) + cipher.encryptor().finalize()
    return encrypted_message


# Funkcija prima dekriptirani ključ, enkriptiranu poruku i inicijalizacijski vektor
# Funcija vraća dekriptiranu jasnu poruku
def decrypt_message(decrypted_key, encrypted_message, iv):
    decrypt_cipher = get_cipher(decrypted_key, iv)
    decrypted_message = decrypt_cipher.decryptor().update(encrypted_message) + decrypt_cipher.decryptor().finalize()
    unpadder = padding.PKCS7(len(iv) * 8).unpadder()
    message = unpadder.update(decrypted_message) + unpadder.finalize()
    message = message.decode()
    return message


# Funkcija prima dekriptirani ključ i inicijalizacijski vektor
# Vraća šifru potrebnu za dekriptiranje poruke
def get_cipher(decrypted_key, iv):
    print('Odaberi simetrični algoritam za dekripciju: a) AES\tb) 3-DES')
    alg = input('[a/b]? : ')

    print('Odaberite način dekriptiranja: a) CBC\tb) CFB')
    encrypt_mode = input('[a/b]? : ')
    mode = modes.CBC(iv) if encrypt_mode == 'a' else modes.CFB(iv)

    if alg == 'a':
        cipher = Cipher(algorithms.AES(decrypted_key), mode, backend=default_backend())
        return cipher
    elif alg == 'b':
        cipher = Cipher(algorithms.TripleDES(decrypted_key), mode, backend=default_backend())
        return cipher


# Funkcijom se odabire algoritam za enkripciju, način kriptiranja i veličinu ključa ovisno o odabranom algoritmu
# Funkcija vraća enkriptiranu poruku i simetrični ključ K
def make_encrypted_message_key():
    print('Odaberi simetrični algoritam za enkripciju: a) AES\tb) 3-DES')
    alg = input('[a/b]? : ')

    print('Odaberite način kriptiranja: a) CBC\tb) CFB')
    encrypt_mode = input('[a/b]? : ')

    # AES
    if alg == 'a':
        key_sizes = [16, 24, 32]
        print('Odaberi veličinu ključa za AES: 1) 128\t2) 192\t3) 256')
        size = input('[1/2/3]? : ')
        key = os.urandom(key_sizes[int(size) - 1])

        iv = os.urandom(16)
        env_iv = input('Ime datoteke u koju želite spremiti inicijalizacijski vektor: ')
        Main.save_files([env_iv], [iv])

        mode = modes.CBC(iv) if encrypt_mode == 'a' else modes.CFB(iv)
        cipher = Cipher(algorithms.AES(key), mode, backend=default_backend())

        encrypted_message = encrypt_message(cipher, len(iv) * 8)
        return encrypted_message, key

    # 3-DES
    elif alg == 'b':
        key_sizes = [8, 16, 24]
        print('Odaberi veličinu ključa za 3-DES: 1) 64\t2) 128\t3) 192')
        size = input('[1/2/3]? : ')
        key = os.urandom(key_sizes[int(size) - 1])

        iv = os.urandom(8)
        env_iv = input('Ime datoteke inicijalizacijskog vektora: ')
        Main.save_files([env_iv], [iv])

        mode = modes.CBC(iv) if encrypt_mode == 'a' else modes.CFB(iv)
        cipher = Cipher(algorithms.TripleDES(key), mode, backend=default_backend())

        encrypted_message = encrypt_message(cipher, len(iv) * 8)
        return encrypted_message, key


# Funkcija služi za odabir hash funkcije za izračunavanje sažetka poruke, te vraća odabranu hash funkciju
def get_encrypt_decrypt_hash():
    print('Odaberite inačicu SHA algoritma: a) SHA-256\tb) SHA-512')
    sha_size = input('[a/b]? : ')
    sha_hash = hashes.SHA256() if sha_size == 'a' else hashes.SHA512()
    return sha_hash


# Funkcija za enkriptaciju digitalne omotnice
# Prima javni ključ primatelja
def encrypt_digital_envelope(public_key):
    print('\n- Enkriptiramo javnim ključem primatelja -\n')

    encrypt_hash = get_encrypt_decrypt_hash()

    encrypted_message, symmetric_key = make_encrypted_message_key()
    encrypted_key = public_key.encrypt(symmetric_key, a_padding.OAEP(mgf=a_padding.MGF1(algorithm=encrypt_hash),
                                                                     algorithm=encrypt_hash,
                                                                     label=None))

    env_enc_message = input('Ime datoteke u koju želite spremiti enkriptiranu poruku P: ')
    env_enc_key = input('Ime datoteke u koju želite spremiti enkriptirani tajni ključ K: ')
    Main.save_files([env_enc_message, env_enc_key], [encrypted_message, encrypted_key])

    # print('\nEnkripcija uspješno obavljena.\n')


# Funkcija za dekriptaciju digitalne omotnice
# Prima privatni ključ primatelja, enkriptiranu poruku, enkriptirani ključ i inicijalizacijski vektor
def decrypt_digital_envelope(private_key, encrypted_message, encrypted_key, iv):
    print('\n- Dekriptiramo svojim privatnim ključem -\n')

    decrypt_hash = get_encrypt_decrypt_hash()

    decrypted_key = private_key.decrypt(encrypted_key, a_padding.OAEP(mgf=a_padding.MGF1(algorithm=decrypt_hash),
                                                                      algorithm=decrypt_hash,
                                                                      label=None))
    decrypted_message = decrypt_message(decrypted_key, encrypted_message, iv)

    print('\nDekriptirana poruka:')
    print('\t' + decrypted_message)
