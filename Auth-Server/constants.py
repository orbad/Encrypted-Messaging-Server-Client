from enum import Enum
from encryptor import AES_KEY_SIZE

PACKET_SIZE = 1024
SERVER_VER = 24
UUID_BYTES = 16
REQ_HEADER_SIZE = 23
DB_NAME = 'clients.info'
MSG_INFO = 'msg.info'
USER_LENGTH = 255
PASSWORD_LENGTH = 255
DEFAULT_PORT = 1256
DEFAULT_MSG_PORT = 1257
PUB_KEY_LEN = 160
SIZE_UINT32_T = 4
MAX_FILE_LEN = 255
MAX_AES_LEN = 128


class RequestCode(Enum):
    CLIENT_REGISTER_REQUEST = 1024
    # SERVER_REGISTER_REQUEST = 1025
    # SERVER_LIST_REQUEST = 1026
    MSG_ENC_KEY_REQUEST = 1027
    LOGIN_REQUEST = 1999


class ResponseCode(Enum):
    REGISTER_SUCCESS = 1600
    REGISTER_ERROR = 1601
    MSG_ENC_KEY_RECEIVED = 1603
    GENERAL_ERROR = 1609
