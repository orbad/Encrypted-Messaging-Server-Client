import socket
import struct

from protocol import Request, Response
from constants import *
from utils import *
from database import Database
from datetime import datetime, timedelta
import uuid
from encryptor import Encryptor
from _thread import *
import threading
import hashlib, base64

print_lock = threading.Lock()


class Server:
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.loggedUser = False
        self.database = Database(DB_NAME)
        self.AESKey = ''
        self.clientUUID = ''
        self.userPassword = ''

    def read(self, conn):
        data = conn.recv(PACKET_SIZE)
        if data:
            self.handleRequest(conn, data)

        print_lock.release()
        conn.close()

    def run(self):
        """
        Start running the server and listen for incoming connections.
        The infinite loop is contained here.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(
                f'Server is running on port {self.port}, listening for connections..')
        except Exception as e:
            print(f'Error occurred: {e}')
            return False

        while True:
            conn, addr = sock.accept()
            print_lock.acquire()
            print(f'Accepted connection from {addr[0]}:{addr[1]}')
            start_new_thread(self.read, (conn,))

    def handleRequest(self, conn, data):
        """ This function handles the request from the client. """
        currRequest = Request()
        currRequest.littleEndianUnpack(data)

        requestedService = currRequest.code
        if requestedService == RequestCode.CLIENT_REGISTER_REQUEST.value:
            self.registerUser(conn, currRequest)

        elif requestedService == RequestCode.MSG_ENC_KEY_REQUEST.value:  # Handle login requests
            self.sendEncMsgKey(conn, currRequest)

        else:
            return

    def hash_password(self, password):
        # Hash a password using SHA-256
        self.userPassword = password
        sha_signature = hashlib.sha256(password.encode()).digest()
        return sha_signature

    def registerUser(self, conn, currRequest):
        """ Registers user. If name exists, returns error.
            Otherwise, creates UUID, saves in memory and DB. """
        currResponse = Response(
            ResponseCode.REGISTER_SUCCESS.value, UUID_BYTES)
        try:
            parts = currRequest.payload.split(b'\x00', 1)  # Split by the first null byte
            user = parts[0].decode('utf-8')  # Decode the username part
            password = parts[1].decode('utf-8') if len(parts) > 1 else ''  # Decode the password part, if present
        except Exception as e:
            print(f'Error decoding payload: {e}')
            return

        try:
            if self.database.isExistentUser(user):
                currResponse.code = ResponseCode.REGISTER_ERROR.value
                currResponse.payloadSize = 0
                data = currResponse.littleEndianPack()
                print(f'Error registering {user}, the user already exists')

            else:
                self.clientUUID = bytes.fromhex(uuid.uuid4().hex)
                hashed_password = self.hash_password(password)
                self.database.registerClient(self.clientUUID.hex(), user, hashed_password.hex(), str(datetime.now()))
                currResponse.payload = self.clientUUID
                print(f'Successfully registered {user} with UUID of {self.clientUUID.hex()}.\n')
                data = currResponse.littleEndianPack()
        except Exception as e:
            currResponse.code = ResponseCode.GENERAL_ERROR.value
            currResponse.payloadSize = 0
            data = currResponse.littleEndianPack()
            print(f'Error: Failed to register user - {e}.')
        sendPacket(conn, data)

    def sendEncMsgKey(self, conn, currRequest):
        enc = Encryptor()
        try:
            req_payload = currRequest.payload
            server_uuid = req_payload[:UUID_BYTES]
            nonce = req_payload[UUID_BYTES:]

            # Load necessary data
            client_uuid_bin = currRequest.uuid
            client_uuid_str = client_uuid_bin.hex()
            user_hashed_password_str = self.database.getUserPassword(client_uuid_str)
            if user_hashed_password_str is not None:
                user_hashed_password = bytes.fromhex(user_hashed_password_str)
                # Generate IVs for encryption
                enc_key_iv = enc.generateIV()
                ticket_iv = enc.generateIV()

                # Encrypt nonce and AES key with user's hashed password
                encrypted_nonce = enc.encryptAES(nonce, user_hashed_password, enc_key_iv)
                server_aes_key = base64.b64decode(self.database.loadMessageServerKey())
                mutual_key = enc.key
                encrypted_aes_key_user = enc.encryptAES(mutual_key, user_hashed_password,
                                                        enc_key_iv)  # AES key encrypted with user's password

                # Prepare ticket components
                encrypted_aes_key_server = enc.encryptAES(mutual_key, server_aes_key,
                                                          ticket_iv)  # AES key encrypted with server's key
                creation_time = int(datetime.now().timestamp())
                expiration_time = int((datetime.now() + timedelta(hours=1)).timestamp())
                encrypted_expiration_time = enc.encryptAES(expiration_time.to_bytes(8, 'little'), server_aes_key,
                                                           ticket_iv)

                # Assemble response payload
                payload = (client_uuid_bin + enc_key_iv + encrypted_nonce + encrypted_aes_key_user +
                           int.to_bytes(SERVER_VER) + client_uuid_bin + server_uuid +
                           struct.pack('<Q', creation_time) + ticket_iv + encrypted_aes_key_server +
                           encrypted_expiration_time)

                self.database.updateLastSeen(client_uuid_str, str(datetime.now()))
                currResponse = Response(ResponseCode.MSG_ENC_KEY_RECEIVED.value, len(payload))
                currResponse.payload = payload
                data = currResponse.littleEndianPack()
                print(f"Encrypted AES-Key and Ticket to the Message-Server was sent to user {client_uuid_str}\n")
                sendPacket(conn, data)
            else:
                raise Exception

        except Exception as e:
            print(f'Error in sendEncMsgKey.')
            # Send error response
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)
            data = currResponse.littleEndianPack()
            sendPacket(conn, data)
