""" Name: Or Badani
    ID: 316307586 """

import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

AES_KEY_SIZE = 32
IV_SIZE = 16


class Encryptor:
    def __init__(self) -> None:
        self.iv = b'\x00' * AES.block_size
        self.key = os.urandom(AES_KEY_SIZE)

    def encryptPubKey(self, text: bytes, pubkey: bytes) -> bytes:
        """ Encrypts the text using a given public RSA key """
        rsa_pubkey = RSA.importKey(pubkey)
        rsa_pubkey = PKCS1_OAEP.new(rsa_pubkey)
        return rsa_pubkey.encrypt(text)

    def generateIV(self):
        return os.urandom(IV_SIZE)

    def decryptAES(self, text: bytes, aeskey: bytes, iv: bytes):
        """ Decrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        raw = cipher.decrypt(text)
        return unpad(raw, AES.block_size)

    def encryptAES(self, text: bytes, aeskey: bytes, iv: bytes) -> bytes:
        """ Encrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(text, AES.block_size))
