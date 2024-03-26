import base64
import socket
import time

from protocol import Request, Response
from constants import *
from utils import *
from datetime import datetime
from encryptor import Encryptor
from _thread import *
import threading
import struct

print_lock = threading.Lock()


class Server:

    def __init__(self) -> None:
        self.address = ''
        self.host = ''
        self.port = ''
        self.loggedUser = False
        self.srvUUID = ''
        self.ticket_AESKey = ''
        self.user_AESKey = ''

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
            sock.bind((self.address, self.port))
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

        if requestedService == RequestCode.SYMM_KEY_SEND_AUTH_SERVER.value:
            self.clientSymmKey(conn, currRequest)
        elif requestedService == RequestCode.MESSAGE_REQUEST.value:  # Handle login requests
            self.gotMessage(conn, currRequest)
        else:
            return

    def loadMessageServerKey(self):
        try:
            with open(MSG_INFO, 'r') as file:
                content = file.readlines()
                return content[3]
        except Exception as e:
            print(f"Failed to save client data: {e}")
    
    def gotMessage(self, conn, currRequest):
        encryptor = Encryptor()
        self.loggedUser = True

        try:
            connected_user_UUID = currRequest.uuid.hex()

            # Extract the payload
            payload = currRequest.payload
            offset = 0
            currResponse = Response(
                ResponseCode.MESSAGE_ACK.value, UUID_BYTES)
            try:
                message_size_bytes = payload[offset:offset+MESSAGE_SIZE]
                offset += MESSAGE_SIZE
                messageIV = payload[offset:offset+IV_SIZE]
                offset += IV_SIZE
                enc_message = payload[offset:]
            except Exception as e:
                print(f'Error decoding payload: {e}')
                # Handle decoding error (e.g., send an error response back to the client)
                return
            message_decrypted = encryptor.decryptAES(enc_message, self.user_AESKey, messageIV).decode("utf-8")
            now = datetime.now()
            time_string = now.strftime("%H:%M:%S")
            print(f"({time_string}) - The user (UUID:{connected_user_UUID}) has sent:\n{message_decrypted}\n")
            currResponse.payloadSize = 0
            data = currResponse.littleEndianPack()
        except Exception as e:
            currResponse.code = ResponseCode.GENERAL_ERROR.value
            currResponse.payloadSize = 0
            data = currResponse.littleEndianPack()
            print(f'Error: Failed to get message from {connected_user_UUID}.')
        sendPacket(conn, data)
    
    def clientSymmKey(self, conn, currRequest):
        encryptor = Encryptor()
        try:
            payloadSize = currRequest.payloadSize
            code = currRequest.code
            version = currRequest.version
            connected_user_UUID = currRequest.uuid.hex()

            # Extract the payload
            payload = currRequest.payload
            currResponse = Response(
                ResponseCode.SYMM_KEY_RECEVIED.value, UUID_BYTES)
            try:
                authenticator_encrypted = payload[:AUTHENTICATOR_SIZE]  # Decode the authenticator part
                ticket_encrypted = payload[AUTHENTICATOR_SIZE:]  # Decode the ticket
            except Exception as e:
                print(f'Error decoding payload: {e}')
                # Handle decoding error (e.g., send an error response back to the client)
                return

            #if authenticator and ticket:
            self.ticket_AESKey = base64.b64decode(self.loadMessageServerKey())
            time.sleep(1)
            authenticator_parsed = parse_authenticator(authenticator_encrypted)
            enc_key_iv, server_version, enc_client_UUID, enc_server_UUID, enc_creation_time = authenticator_parsed
            ticket_parsed = parse_ticket(ticket_encrypted)
            ticket_version, client_UUID, server_UUID, creation_time, ticket_iv, enc_server_AES, enc_expiration_time = ticket_parsed
            self.user_AESKey = encryptor.decryptAES(enc_server_AES, self.ticket_AESKey, ticket_iv)
            auth_ver_decrypted = int.from_bytes(encryptor.decryptAES(server_version, self.user_AESKey, enc_key_iv))
            auth_client_UUID_dec = encryptor.decryptAES(enc_client_UUID, self.user_AESKey, enc_key_iv)
            auth_server_UUID_dec = encryptor.decryptAES(enc_server_UUID, self.user_AESKey, enc_key_iv)
            auth_creation_time_dec_bytes = encryptor.decryptAES(enc_creation_time, self.user_AESKey, enc_key_iv)
            auth_creation_time_dec = int.from_bytes(auth_creation_time_dec_bytes, 'little')
            ticket_version_dec = ticket_version
            ticket_client_UUID = client_UUID
            ticket_server_UUID = server_UUID
            ticket_creation_time = creation_time
            ticket_expiration_time_decrypted = encryptor.decryptAES(enc_expiration_time, self.ticket_AESKey, ticket_iv)
            verified_user = verify_and_respond(auth_client_UUID_dec, auth_server_UUID_dec, auth_creation_time_dec, auth_ver_decrypted, ticket_client_UUID, ticket_server_UUID, ticket_creation_time, int.from_bytes(ticket_expiration_time_decrypted), ticket_version_dec)

            if verified_user:
                currResponse.payloadSize = 0
                data = currResponse.littleEndianPack()
                print(f"AES KEY was Received Successfully from User: {connected_user_UUID}")
            else:
                currResponse.code = ResponseCode.GENERAL_ERROR.value
                currResponse.payloadSize = 0
                data = currResponse.littleEndianPack()
                print(f'Error: Failed to get Authenticator Ticket from {connected_user_UUID}.')
        except Exception as e:
            currResponse.code = ResponseCode.GENERAL_ERROR.value
            currResponse.payloadSize = 0
            data = currResponse.littleEndianPack()
            print(f'Error: Failed to get Authenticator Ticket from {connected_user_UUID}.')
        sendPacket(conn, data)
