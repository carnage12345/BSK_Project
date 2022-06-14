#import rsa
import hashlib
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto.Util.Padding import pad, unpad


#  RSA key functions
# --------
# Jaworski
# --------

def generate_keys(letter):
    privateKey = RSA.generate(1024)
    publicKey = privateKey.public_key()
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
        f.write(publicKey.exportKey('PEM'))
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
        f.write(privateKey.exportKey('PEM'))

    print("Keys Generated")


def load_keys(letter):
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
        publicKey = RSA.importKey(f.read())
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
        privateKey = RSA.importKey(f.read())

    return publicKey, privateKey


def generate_keys_secret(letter, localKey):
    privateKey = RSA.generate(1024)
    publicKey = privateKey.public_key()
    ivPrivate, secretPrivateKey = encrypt_rsa_key_with_local_key(privateKey.exportKey("PEM").decode(), localKey)
    ivPublic, secretPublicKey = encrypt_rsa_key_with_local_key(publicKey.exportKey("PEM").decode(), localKey)
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'wb') as f:
        f.write(secretPrivateKey)
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'wb') as f:
        f.write(secretPublicKey)
    with open('./Keys' + letter + '/PrivateKeys/ivPrivate.txt', 'wb') as f:
        f.write(ivPrivate)
    with open('./Keys' + letter + '/PublicKeys/ivPublic.txt', 'wb') as f:
        f.write(ivPublic)

    print("Secret Keys Generated")
    return ivPrivate, ivPublic


def load_keys_secret(letter, localKey):
    with open('./Keys' + letter + '/PrivateKeys/privateKey' + letter + '.pem', 'rb') as f:
        secretPrivateKey = f.read()
    with open('./Keys' + letter + '/PublicKeys/publicKey' + letter + '.pem', 'rb') as f:
        secretPublicKey = f.read()
    with open('./Keys' + letter + '/PrivateKeys/ivPrivate.txt', 'rb') as f:
        ivPrivate = f.read()
    with open('./Keys' + letter + '/PublicKeys/ivPublic.txt', 'rb') as f:
        ivPublic = f.read()

    try:
        decryptedPrivateKey = decrypt_rsa_key_with_local_key(secretPrivateKey, localKey, ivPrivate).decode()
        decryptedPublicKey = decrypt_rsa_key_with_local_key(secretPublicKey, localKey, ivPublic).decode()
        privateKey = RSA.importKey(decryptedPrivateKey)
        publicKey = RSA.importKey(decryptedPublicKey)
        return publicKey, privateKey
    except:
        return False, False





#  ---my local key ---
def encrypt_rsa_key_with_local_key(rsaKey, localKey):
    cipherCBC = AES.new(localKey, AES.MODE_CBC)
    iVector = cipherCBC.iv
    return iVector, cipherCBC.encrypt(pad(rsaKey.encode("utf-8"), AES.block_size))


def decrypt_rsa_key_with_local_key(rsaKey, localKey, iVector):
    cipherCBC = AES.new(localKey, AES.MODE_CBC, iVector)
    try:
        return unpad(cipherCBC.decrypt(rsaKey), AES.block_size)
    except:
        return False


def hashPassword(password):
    hashed_password = hashlib.sha256(password.encode("utf-8")).digest()
    return hashed_password


# ---end my local key ---
def encrypt(message, publicKey):
    #return rsa.encrypt(message.encode('utf-8'), key)
    encryptor = PKCS1_OAEP.new(publicKey)
    return encryptor.encrypt(message.encode("utf-8"))


def decrypt(cipherText, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    try:
        return decryptor.decrypt(cipherText).decode("utf-8")
    except:
        return False


def encrypt_session_key_with_rsa(session_key, publicKey):
    encryptor = PKCS1_OAEP.new(publicKey)
    return encryptor.encrypt(session_key)


def decrypt_session_key_with_rsa(session_key_encoded, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    try:
        return decryptor.decrypt(session_key_encoded)
    except:
        return False

