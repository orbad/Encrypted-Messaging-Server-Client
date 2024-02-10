""" Name: Or Badani
    ID: 316307586 """

import socket
from protocol import Request, Response
from constants import *
from utils import *
from database import Database
from datetime import datetime
import uuid
from encryptor import Encryptor
from _thread import *
import threading
import hashlib


print_lock = threading.Lock()


class Server:
    MAX_TRIES = 3

    def __init__(self, host, port, messagePort) -> None:
        self.host = host
        self.port = port
        self.messagePort = messagePort
        self.loggedUser = False
        self.database = Database(DB_NAME)
        self.AESKey = ''

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
        elif requestedService == RequestCode.LOGIN_REQUEST.value:  # Handle login requests
            self.loginUser(conn, currRequest)
        # elif requestedService == RequestCode.PUB_KEY_SEND.value or RequestCode.FILE_SEND.value:
        #     self.fileUpload(conn, currRequest)
        else:
            return

    def hash_password(self, password):
        # Hash a password using SHA-256
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
            # Handle decoding error (e.g., send an error response back to the client)
            return

        try:
            if self.database.isExistentUser(user):
                currResponse.code = ResponseCode.REGISTER_ERROR.value
                currResponse.payloadSize = 0
                data = currResponse.littleEndianPack()
                print(f'Error registering {user}, the user already exists')

            else:
                id = bytes.fromhex(uuid.uuid4().hex)
                hashed_password = self.hash_password(password)
                self.database.registerClient(id.hex(), user, hashed_password.hex(), str(datetime.now()))
                currResponse.payload = id
                print(f'Successfully registered {user} with UUID of {id.hex()}.')
                data = currResponse.littleEndianPack()
        except Exception as e:
            currResponse.code = ResponseCode.GENERAL_ERROR.value
            currResponse.payloadSize = 0
            data = currResponse.littleEndianPack()
            print(f'Error: Failed to register user - {e}.')
        sendPacket(conn, data)

    def sendPubKey(self, conn, currRequest):
        """ Receives a public key, generates AES key, and sends it, only applies for new users. """
        enc = Encryptor()
        offset = currRequest.payloadSize - PUB_KEY_LEN
        username = currRequest.payload[:offset].decode('utf-8')
        pubkey = currRequest.payload[offset:]

        self.database.setPubKey(currRequest.uuid, pubkey)

        print(f'Received request for AES key from {username}.')
        currResponse = Response(
            ResponseCode.PUB_KEY_RECEVIED.value, UUID_BYTES + MAX_AES_LEN)

        try:
            self.database.setAESKey(currRequest.uuid, enc.key)

            encAESKey = enc.encryptPubKey(enc.key, pubkey)
            currResponse.payload = currRequest.uuid + encAESKey
            data = currResponse.littleEndianPack()
            sendPacket(conn, data)
            print(f'AES key successfully sent to {username}.')
            return enc.key
        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            data = currResponse.littleEndianPack()
            sendPacket(conn, data)
            print(f'Error: Failed to send Pubkey - {e}.')


    def loginUser(self, conn, currRequest):
        """ Logs in a user. If name doesn't exist and RSA not found, returns error.
            Otherwise, returns the UUID and AES key of the user. """
        enc = Encryptor()
        offset = currRequest.payloadSize
        username = currRequest.payload[:offset].decode('utf-8')
        user_info = self.database.getUserInfo(
            username)  # Assume getUserInfo method retrieves the UUID and AES key for a given username
        try:
            if user_info is None:
                # User not found in the database
                currResponse = Response(ResponseCode.LOGIN_ERROR.value, 0)  # No UUID if user didn't appear in DB
                print(f"Failed login attempt with username: {username}")
            else:
                # User found in the database
                if 'PublicKey' in user_info:
                    user_uuid = user_info['UUID']
                    aes_key = user_info['AESKey']
                    self.AESKey = aes_key
                    encAESKey = enc.encryptPubKey(aes_key, user_info['PublicKey'])
                    currResponse = Response(ResponseCode.LOGIN_SUCCESS.value,
                                            UUID_BYTES + MAX_AES_LEN)  # Payload size is the size of a UUID plus the size of an AES key
                    currResponse.payload = user_uuid + encAESKey  # Set the payload to the user's UUID concatenated with the AES key
                    self.loggedUser = True
                    print(f"Successfully logged in user {username} with UUID: {user_uuid.hex()}")
                else:
                    currResponse = Response(ResponseCode.LOGIN_ERROR.value, user_info['UUID'] if user_info['UUID'] else 0)  # Return UUID payload for login error, no payload if doesn't exist in DB
                    print(f"Failed login attempt with username: {username}")
        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            print(f'Error: Failed to login user - {e}.')

        data = currResponse.littleEndianPack()
        sendPacket(conn, data)  # Send response back to the client

    # def fileUpload(self, conn, currRequest):
    #     """ Handles upload of file, including encryption. """
    #     if currRequest.code == RequestCode.PUB_KEY_SEND.value:
    #         AESKey = self.sendPubKey(conn, currRequest)
    #         buffer = conn.recv(PACKET_SIZE)
    #         currRequest.littleEndianUnpack(buffer)
    #     else:
    #         AESKey = self.AESKey
    #     crc_confirmed = False
    #     tries = 0
    #
    #     while tries < Server.MAX_TRIES and not crc_confirmed:
    #         if currRequest.code != RequestCode.FILE_SEND.value:
    #             return
    #         contentSize = currRequest.payload[:SIZE_UINT32_T]
    #         filename = currRequest.payload[SIZE_UINT32_T:SIZE_UINT32_T +
    #                                                      MAX_FILE_LEN].decode('utf-8')
    #         enc_content = currRequest.payload[SIZE_UINT32_T + MAX_FILE_LEN:]
    #         currPayloadSize = min(currRequest.payloadSize,
    #                               PACKET_SIZE - REQ_HEADER_SIZE)
    #
    #         sizeLeft = currRequest.payloadSize - currPayloadSize
    #         while sizeLeft > 0:
    #             tempPayload = conn.recv(PACKET_SIZE)
    #             currPayloadSize = min(sizeLeft, PACKET_SIZE)
    #             enc_content += tempPayload[:currPayloadSize]
    #             sizeLeft -= currPayloadSize
    #
    #         wrapper = Encryptor()
    #         dec_content = wrapper.decryptAES(enc_content, AESKey)
    #
    #         # Calculate checksum
    #         digest = crc.crc32()
    #         digest.update(dec_content)
    #         checksum = digest.digest()
    #
    #         # Send Response 2103
    #         resPayloadSize = 2 * SIZE_UINT32_T + MAX_FILE_LEN
    #         newResponse = Response(
    #             ResponseCode.FILE_OK_CRC.value, resPayloadSize)
    #         newResponse.payload = contentSize + filename.encode('utf-8')
    #         newResponse.payload += struct.pack('<I', checksum)
    #         buffer = newResponse.littleEndianPack()
    #         sendPacket(conn, buffer)
    #
    #         # Receive confirmation for CRC.
    #         buffer = conn.recv(PACKET_SIZE)
    #         currRequest.littleEndianUnpack(buffer)
    #         if currRequest.code == RequestCode.CRC_OK.value:
    #             crc_confirmed = True
    #             print("CRC confirmed, backing up the file.")
    #         elif currRequest.code == RequestCode.CRC_INVALID_RETRY.value:
    #             tries += 1
    #             print("Failed to confirm CRC, waiting for user to try again.")
    #         elif currRequest.code == RequestCode.CRC_INVALID_EXIT.value:
    #             print("Failed to confirm CRC after total of 4 invalid CRC.\nFile transfer is not verified.")
    #             return
    #     # End of while loop
    #
    #     finalRes = Response(ResponseCode.MSG_RECEIVED.value, 0)
    #     buffer = finalRes.littleEndianPack()
    #
    #     createDirectory('backup')
    #     dec_filename = filename.split("\x00")[0]
    #     pathname = 'backup\\' + dec_filename
    #     try:
    #         f = open(pathname, 'wb')
    #         f.write(dec_content)
    #         f.close()
    #         self.database.registerFile(
    #             currRequest.uuid, dec_filename, pathname, 1)
    #         # print(self.database.executeCommand("SELECT * FROM clients"))
    #         # print(self.database.executeCommand("SELECT * FROM files"))
    #         print(f'Successfully backed up file {dec_filename}.')
    #         sendPacket(conn, buffer)
    #     except Exception as e:
    #         currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
    #         buffer = currResponse.littleEndianPack()
    #         sendPacket(conn, buffer)
    #         print(f'Error: Failed to write to backup - {e}.')
