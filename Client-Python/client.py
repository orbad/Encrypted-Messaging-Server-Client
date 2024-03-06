import base64
import socket
import os
import sys
import time
from datetime import datetime

from constants import *
from encryptor import *
from utils import parse_response
import struct
import hashlib
import json, uuid


class Client:
    def __init__(self):
        self.uuid = ''
        self.username = ''
        self.password = ''
        self.hashed_password = ''
        self.auth_server_address = ''
        self.msg_server_address = ''
        self.msgAES = ''
        self.nonce = ''
        self.auth_port = ''
        self.creation_time = ''
        self.ticket_msg = ''
        self.sock = None

    def connect(self, server_address, server_port):
        """Attempts to establish a connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((server_address, server_port))
            print(f"Connected to {server_address}:{server_port}")
            return True
        except socket.error as err:
            print(f"Connection failed: {err}")
            self.sock = None
            return False

    def close(self):
        """Closes the socket connection."""
        if self.sock:
            self.sock.close()
            print("Connection closed")

    def hex_string_to_binary(self, hex_str):
        """Convert a hexadecimal string to its binary representation."""
        return bytes.fromhex(hex_str)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def send_msg(self, server_address, server_port, user_uuid, message_payload):
        if not self.connect(server_address, server_port):
            return False  # Connection failed
        encryptor = Encryptor()
        messageIV = encryptor.generateIV()
        message_payload_enc = encryptor.encryptAES(message_payload.encode("utf-8"), self.msgAES, messageIV)
        message_size_enc = int.to_bytes(len(message_payload_enc), 4, byteorder='little')
        payload = message_size_enc + messageIV + message_payload_enc
        payload_size = len(payload)  # For null terminators
        client_id_bin = self.hex_string_to_binary(user_uuid)  # Assuming UUID is provided in hex
        code = RequestCode.MSG_SEND_REQUEST.value
        header = struct.pack('<16sBHI', client_id_bin, SERVER_VER, code, payload_size)
        packet = header + payload

        # Send the packet
        try:
            self.sock.sendall(packet)
            self.handle_server_response()  # Process server response
        except socket.error as err:
            print(f"Failed to send data: {err}")
            return False
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None  # Ensure the socket is cleaned up
        return True

    def send_msg_encryption_key(self, server_address, server_port, user_uuid, msg_srv_uuid):
        # Create socket
        if not self.connect(server_address, server_port):
            return False  # Connection failed
        encryptor = Encryptor()
        authenticator_IV = encryptor.generateIV()
        hexVerNum = int.to_bytes(SERVER_VER)
        time.sleep(
            1)  # Added sleep in the client's end in order to verify that the Authenticator's creation time happens after the Ticket's creation time.
        creation_time = int(datetime.now().timestamp())
        authenticator_enc_ver = encryptor.encryptAES(hexVerNum, self.msgAES, authenticator_IV)
        print(f"Encrypted Version server size is: {len(authenticator_enc_ver)}")
        authenticator_enc_user_uuid = encryptor.encryptAES(bytes.fromhex(self.uuid), self.msgAES, authenticator_IV)
        authenticator_enc_srv_uuid = encryptor.encryptAES(bytes.fromhex(msg_srv_uuid), self.msgAES, authenticator_IV)
        authenticator_enc_creationTime = encryptor.encryptAES((creation_time).to_bytes(8, 'little'), self.msgAES,
                                                              authenticator_IV)
        print(
            f"Enc_ver: {authenticator_enc_ver}, Enc_user_uuid: {authenticator_enc_user_uuid}, enc_Srv_uuid: {authenticator_enc_srv_uuid}, enc_creationTime:{authenticator_enc_creationTime}")
        authenticator = authenticator_IV + authenticator_enc_ver + authenticator_enc_user_uuid + authenticator_enc_srv_uuid + authenticator_enc_creationTime
        authenticator_size = len(authenticator)
        # Prepare the request payload
        payload = authenticator + self.ticket_msg
        # payload = (msg_srv_uuid + "\x00" + nonce).encode()
        payload_size = authenticator_size + TICKET_SIZE

        # Construct the request header and payload
        client_id_bin = self.hex_string_to_binary(user_uuid)  # Assuming UUID is provided in hex
        code = RequestCode.MSG_ENC_KEY_SEND.value  # Your request code for this operation
        header = struct.pack('<16sBHI', client_id_bin, SERVER_VER, code, payload_size)

        # # Ensure the packet size does not exceed limits
        # if len(header) + payload_size > PACKET_SIZE:
        #     print("Error: Payload size exceeds the packet size limit.")
        #     return False
        #
        # # Combine header and payload

        packet = header + payload

        # Send the packet
        try:
            self.sock.sendall(packet)
            self.handle_server_response()  # Process server response
        except socket.error as err:
            print(f"Failed to send data: {err}")
            return False
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None  # Ensure the socket is cleaned up
        return True

    def get_symm_key(self, server_address, server_port, user_uuid, msg_srv_uuid):
        # Create socket
        if not self.connect(server_address, server_port):
            return False  # Connection failed
        encryptor = Encryptor()
        nonce = encryptor.generateNonce()
        print(f"Sending the following UUID: \n{msg_srv_uuid}.\n")
        print(f"Sending the following NONCE: \n{nonce.hex()}.\n")
        print(f"From the UUID: \n{user_uuid}.\n")

        # Convert UUID and nonce from hex to binary
        msg_srv_uuid_bin = bytes.fromhex(msg_srv_uuid)

        # Prepare the request payload
        payload = msg_srv_uuid_bin + nonce
        # payload = (msg_srv_uuid + "\x00" + nonce).encode()
        payload_size = UUID_BYTES + NONCE_SIZE  # +1 for null terminator, if needed

        # Construct the request header and payload
        client_id_bin = self.hex_string_to_binary(user_uuid)  # Assuming UUID is provided in hex
        code = RequestCode.MSG_ENC_KEY_REQUEST.value  # Your request code for this operation
        header = struct.pack('<16sBHI', client_id_bin, SERVER_VER, code, payload_size)

        # Ensure the packet size does not exceed limits
        if len(header) + payload_size > PACKET_SIZE:
            print("Error: Payload size exceeds the packet size limit.")
            return False

        # Combine header and payload
        packet = header + payload

        # Send the packet
        try:
            self.sock.sendall(packet)
            self.handle_server_response()  # Process server response
        except socket.error as err:
            print(f"Failed to send data: {err}")
            return False
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None  # Ensure the socket is cleaned up
        return True

        # Receive and process the response
        # Omitted for brevity - include your logic to handle the server's response

        # sock.close()
        # return True

    def handle_server_response(self):
        """Handles the server response after sending the registration request."""
        buffer = self.sock.recv(PACKET_SIZE)
        # Response header format is: version (1 byte), code (2 bytes), payload_size (4 bytes)
        version, code, payload_size = struct.unpack('<BHI', buffer[:7])

        if code == ResponseCode.REGISTER_ERROR.value:
            print("Error: Failed to register user, the user is already registered, try to login instead.")
            sys.exit(1)
        elif code == ResponseCode.REGISTER_SUCCESS.value:
            self.update_me_info(buffer[7:7 + payload_size])
            print("Updated ME INFO file with name and UUID.")
        elif code == ResponseCode.MSG_ENC_KEY_RECEIVED.value:
            parsed_fields = parse_response(buffer)
            client_uuid, ticket_IV, encrypted_nonce, encrypted_aes_key, self.ticket_msg = parsed_fields
            enc = Encryptor()
            hashed_password_bytes = bytes.fromhex(self.hashed_password)
            print(f"This is the hashed password: {self.hashed_password}")
            self.nonce = enc.decryptAES(encrypted_nonce, hashed_password_bytes, ticket_IV)
            self.msgAES = enc.decryptAES(encrypted_aes_key, hashed_password_bytes, ticket_IV)
            print(f"This is the msgAES:{base64.b64encode(self.msgAES)} and this is the ticket_IV:{base64.b64encode(ticket_IV)}")
            print("Successfully retrieved Encrypted AES key from Auth Server")
        elif code == ResponseCode.MSG_ENC_KEY_SENT_SUCCESS.value:
            print("Encryption key was sent successfully to the message server.")
        elif code == ResponseCode.MSG_RECEIVED_ACK.value:
            print("Message sent successfully to the message server!")

        elif code == ResponseCode.GENERAL_ERROR.value:
            print("The previous action was failed.")
            sys.exit(1)
        else:
            print("Received an unknown response code.")

    def update_me_info(self, payload):
        """Updates the ME_INFO file with the received UUID."""
        does_me_exist = self.is_existent(ME_INFO)
        mode = 'w' if not does_me_exist else 'a'  # Write mode if file does not exist, append mode otherwise

        with open(ME_INFO, mode) as file:
            if does_me_exist:
                file.write("\n")
            file.write(f"{self.username}\n")
            # Convert payload (UUID in bytes) to a hexadecimal string before writing
            self.uuid = payload.hex()
            file.write(self.uuid)

    def is_existent(self, file_path):
        """Check if a file exists."""
        return os.path.exists(file_path)

    def load_client_info(self):
        """Load client information from 'me.info'."""
        if not self.is_existent(ME_INFO):
            print("Error: Me.info file do not exist.")
            return False

        with open(ME_INFO, 'r') as file:
            self.username = file.readline().strip()
            self.uuid = file.readline().strip()

        print("Client - login, username: {}".format(self.username))
        print(f"Client - login, UUID: {self.uuid}")
        return True, self.username, self.uuid

    def register_user(self, server_address, server_port):
        if not self.connect(server_address, server_port):
            return False  # Connection failed

        # Check if ME_INFO exists and obtain username and UUID from it
        if os.path.exists(ME_INFO):
            with open(ME_INFO, 'r') as f:
                self.username = f.readline().strip()
                self.uuid = f.readline().strip()
        else:
            # Prompt user for username and password
            username = input("Enter your username: ")
            if len(username) >= USER_LENGTH:
                print("Username doesn't meet the length criteria.")
                return False
            self.username = username
            password = input("Enter your password: ")
            if len(password) >= PASSWORD_LENGTH:
                print("Password doesn't meet the length criteria.")
                return False
            # Hash the password (This should be replaced by actual password encryption logic)
            self.password = password
            self.hashed_password = self.hash_password(password)

        # Prepare the payload
        payload = (self.username + "\x00" + self.password).encode()

        # Construct the header
        uuid_bytes = uuid.uuid4().bytes  # Random UUID for this example
        code = RequestCode.CLIENT_REGISTER_REQUEST.value
        payload_size = len(payload)
        header = struct.pack('<16sBHI', uuid_bytes, SERVER_VER, code, payload_size)

        # Ensure the packet size does not exceed limits
        if len(header) + payload_size > PACKET_SIZE:
            print("Error: Payload size exceeds the packet size limit.")
            return False

        # Combine header and payload
        packet = header + payload

        # Send the packet
        try:
            self.sock.sendall(packet)
            self.handle_server_response()  # Process server response
        except socket.error as err:
            print(f"Failed to send data: {err}")
            return False
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None  # Ensure the socket is cleaned up
        return True
