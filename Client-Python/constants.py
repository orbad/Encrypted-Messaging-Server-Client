from enum import Enum
from encryptor import AES_KEY_SIZE, IV_SIZE

PACKET_SIZE = 1024
SERVER_VER = 24
UUID_BYTES = 16
REQ_HEADER_SIZE = 23
RES_HEADER_SIZE = 7
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
ME_INFO = "./me.info"
SRV_INFO = "./srv.info"
MSG_SRV_UUID = "5dd7496abe3c4ea9bf16e0f2b978aff4"
ENC_AES_SIZE = 48
ENC_PASSWORD = 32
NONCE_SIZE = 8
ENC_NONCE_SIZE = 16
SERVER_ID_SIZE = 16
TIMESTAMP_SIZE = 8
ENC_TIMESTAMP_SIZE = 16
TICKET_SIZE = 121


class RequestCode(Enum):
    CLIENT_REGISTER_REQUEST = 1024
    SERVER_REGISTER_REQUEST = 1025 #Bonus
    SERVER_LIST_REQUEST = 1026 #Bonus, payload_size=0
    MSG_ENC_KEY_REQUEST = 1027
    MSG_ENC_KEY_SEND = 1028
    MSG_SEND_REQUEST = 1029



class ResponseCode(Enum):
    REGISTER_SUCCESS = 1600
    REGISTER_ERROR = 1601
    MSG_ENC_KEY_RECEIVED = 1603
    MSG_ENC_KEY_SENT_SUCCESS = 1604
    MSG_RECEIVED_ACK = 1605
    GENERAL_ERROR = 1609
