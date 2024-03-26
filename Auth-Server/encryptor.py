import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

AES_KEY_SIZE = 32
IV_SIZE = 16


class Encryptor:
    def __init__(self) -> None:
        self.iv = b'\x00' * AES.block_size
        self.key = os.urandom(AES_KEY_SIZE)

    def generateIV(self):
        return os.urandom(IV_SIZE)

    def decryptAES(self, text: bytes, aeskey: bytes, iv: bytes):
        """ Decrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        raw = cipher.decrypt(text)
        try:
            return unpad(raw, AES.block_size)
        except ValueError:
            print("User's password is incorrect, exiting..")
            exit(1)
    def encryptAES(self, text: bytes, aeskey: bytes, iv: bytes) -> bytes:
        """ Encrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(text, AES.block_size))