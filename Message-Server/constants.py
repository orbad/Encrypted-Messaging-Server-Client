from enum import Enum
from encryptor import AES_KEY_SIZE

MSG_INFO = './msg.info'
PACKET_SIZE = 1024
SERVER_VER = 24
UUID_BYTES = 16
REQ_HEADER_SIZE = 23
RES_HEADER_SIZE = 7
USER_LENGTH = 255
PASSWORD_LENGTH = 255
DEFAULT_MSG_PORT = 1257
PUB_KEY_LEN = 160
SIZE_UINT32_T = 4
MAX_FILE_LEN = 255
MAX_AES_LEN = 128
IV_SIZE = 16
ENC_AES_SIZE = 48
ENC_PASSWORD = 32
NONCE_SIZE = 8
SERVER_VERSION_SIZE = 1
MESSAGE_SIZE = 4
ENC_NONCE_SIZE = 16
SERVER_ID_SIZE = 16
TIMESTAMP_SIZE = 8
ENC_TIMESTAMP_SIZE = 16
ENC_UUID_SIZE = 32
AUTHENTICATOR_SIZE = 112
TICKET_SIZE = 121

class RequestCode(Enum):
    SYMM_KEY_SEND_AUTH_SERVER = 1028
    MESSAGE_REQUEST = 1029



class ResponseCode(Enum):
    SYMM_KEY_RECEVIED = 1604
    MESSAGE_ACK = 1605
    GENERAL_ERROR = 1609
