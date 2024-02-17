""" Name: Or Badani
    ID: 316307586 """

import socket
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
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

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

        # elif requestedService == RequestCode.PUB_KEY_SEND.value or RequestCode.FILE_SEND.value:
        #     self.fileUpload(conn, currRequest)
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
            # Handle decoding error (e.g., send an error response back to the client)
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
                print(f'Successfully registered {user} with UUID of {self.clientUUID.hex()}.')
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
                if 'PasswordHash' in user_info:
                    user_uuid = user_info['UUID']
                    user_hashedpass = user_info['PasswordHash']
                    aes_key = user_info['AESKey']
                    self.AESKey = aes_key
                    encAESKey = enc.encryptPubKey(aes_key, user_hashedpass)
                    currResponse = Response(ResponseCode.LOGIN_SUCCESS.value,
                                            UUID_BYTES + MAX_AES_LEN)  # Payload size is the size of a UUID plus the size of an AES key
                    currResponse.payload = user_uuid + encAESKey  # Set the payload to the user's UUID concatenated with the AES key
                    self.loggedUser = True
                    print(f"Successfully logged in user {username} with UUID: {user_uuid.hex()}")
                else:
                    currResponse = Response(ResponseCode.LOGIN_ERROR.value, user_info['UUID'] if user_info[
                        'UUID'] else 0)  # Return UUID payload for login error, no payload if doesn't exist in DB
                    print(f"Failed login attempt with username: {username}")
        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            print(f'Error: Failed to login user - {e}.')

        data = currResponse.littleEndianPack()
        sendPacket(conn, data)  # Send response back to the client

    def sendEncMsgKey(self, conn, currRequest):
        enc = Encryptor()
        offset = currRequest.payloadSize

        # buffer = conn.recv(PACKET_SIZE)
        # request_h = currRequest.littleEndianUnpack(buffer)
        # currResponse = Response(ResponseCode.MSG_ENC_KEY_RECEVIED.value, 16 + 16 + 8 + 32 + 1 + 16 + 16 + 8 + 16 + 32 + 8)
        try:
            parts = currRequest.payload.split(b'\x00', 2)  # Split by null bytes to extract UUID and nonce
            server_uuid = parts[0]
            nonce = parts[1]
            # Generate AES Key and IV
            server_aes_key_b64 = self.database.loadMessageServerKey()
            server_aes_key = base64.b64decode(server_aes_key_b64)
            aes_key = enc.key
            client_uuid_str = currRequest.uuid.hex()
            client_uuid_bin = currRequest.uuid
            user_hashed_password = bytes.fromhex(self.database.getUserPassword(client_uuid_str)) # Need to load from DB already hashed
            enc_key_iv = enc.generateIV()  # Generate a new IV for user encryption
            ticket_iv = enc.generateIV()  # Generate a new IV for ticket encryption
            # Encrypt the nonce and AES key with the user's hashed password
            encrypted_nonce = enc.encryptAES(nonce, user_hashed_password, enc_key_iv)
            encrypted_aes_key = enc.encryptAES(aes_key, user_hashed_password, enc_key_iv)
            ticket_version = int.to_bytes(SERVER_VER)
            encrypted_ticket_aes_key = enc.encryptAES(aes_key, server_aes_key, ticket_iv)
            creation_time = int(datetime.now().timestamp())
            expiration_time = int((datetime.now() + timedelta(hours=1)).timestamp())
            encrypted_expiration_time = enc.encryptAES(expiration_time.to_bytes(8, 'little'), enc.key, ticket_iv)

            # encrypted_key = b''.join([
            #     enc_key_iv,
            #     encrypted_nonce,
            #     encrypted_aes_key
            # ])
            # ticket_payload = b''.join([
            #     ticket_version,
            #     client_uuid_bin,
            #     server_uuid,
            #     creation_time.to_bytes(8, 'little'),
            #     ticket_iv,
            #     encrypted_ticket_aes_key,
            #     encrypted_expiration_time
            # ])
            # response_payload = b''.join([
            #     client_uuid_bin,
            #     encrypted_key,
            #     ticket_payload
            # ])
            currResponse = Response(ResponseCode.MSG_ENC_KEY_RECEIVED.value, 217)
            currResponse.payload = client_uuid_bin + enc_key_iv + encrypted_nonce + encrypted_aes_key + ticket_version + client_uuid_bin + server_uuid + creation_time.to_bytes(8, 'little') + ticket_iv + encrypted_ticket_aes_key + encrypted_expiration_time
            # currResponse.payload = response_payload
            data = currResponse.littleEndianPack()
            sendPacket(conn, data)

        except Exception as e:
            currResponse = Response(ResponseCode.GENERAL_ERROR.value, 0)  # No UUID if user didn't appear in DB
            data = currResponse.littleEndianPack()
            sendPacket(conn, data)
            print(f'Error: Failed to send Encrypted Key - {e}.')
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
