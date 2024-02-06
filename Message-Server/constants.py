""" Name: Or Badani
    ID: 316307586 """

from enum import Enum
from encryptor import AES_KEY_SIZE

PACKET_SIZE = 1024
SERVER_VER = 24
UUID_BYTES = 16
REQ_HEADER_SIZE = 23
DB_NAME = 'clients.db'
USER_LENGTH = 255
PASSWORD_LENGTH = 255
DEFAULT_PORT = 1256
PUB_KEY_LEN = 160
SIZE_UINT32_T = 4
MAX_FILE_LEN = 255
MAX_AES_LEN = 128


class RequestCode(Enum):
    PUB_KEY_SEND_AUTH_SERVER = 1028
    MESSAGE_REQUEST = 1029



class ResponseCode(Enum):
    MESSAGE_ACK = 1605
    PUB_KEY_RECEVIED = 1604
    GENERAL_ERROR = 1609
