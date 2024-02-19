import socket
import os
import sys
from constants import *
from encryptor import Encryptor
import struct
import hashlib
import json, uuid


class Client:
    def __init__(self):
        self.uuid = ''
        self.username = ''
        self.password = ''
        self.hashed_password = ''
        self.server_address = ''
        self.auth_port = ''
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
        elif code == ResponseCode.GENERAL_ERROR.value:
            print("An error occurred during registration.")
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
            uuid_hex = payload.hex()
            file.write(uuid_hex)

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

        print(f"Client - login, username: {self.username}")
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
            self.hashed_password = hashlib.sha256(password.encode()).hexdigest()

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





