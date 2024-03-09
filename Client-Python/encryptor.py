""" Name: Or Badani
    ID: 316307586 """

import os
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad

AES_KEY_SIZE = 32
IV_SIZE = 16
NONCE_SIZE = 8


class Encryptor:
    def __init__(self) -> None:
        self.iv = b'\x00' * AES.block_size
        self.key = os.urandom(AES_KEY_SIZE)

    def generateNonce(self):
        return os.urandom(NONCE_SIZE)

    def generateIV(self):
        return os.urandom(IV_SIZE)

    def hex_string_to_binary(self, hex_str):
        """Convert a hexadecimal string to its binary representation."""
        return bytes.fromhex(hex_str)

    def decryptAES(self, text: bytes, aeskey: bytes, iv: bytes):
        """ Decrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        raw = cipher.decrypt(text)
        try:
            return unpad(raw, AES.block_size)
        except ValueError:
            if(len(text)>AES_KEY_SIZE): # In order to avoid double printing of ValueError, only enc_AES_KEY should pass this condition.
                print("Decryption failed: Password is incorrect. \nRetry..")
            return None

    def encryptAES(self, text: bytes, aeskey: bytes, iv: bytes) -> bytes:
        """ Encrypts the text using a given AES key and IV """
        cipher = AES.new(aeskey, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(text, AES.block_size))
