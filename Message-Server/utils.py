""" Name: Or Badani
    ID: 316307586 """
from datetime import datetime
import struct

from constants import *

def getPort(filename):
    """
    Gets the port from the file.
    If file doesn't exist, defaults to port 1357. 
    """
    msg_port = DEFAULT_MSG_PORT

    try:
        with open(filename) as f:
            readMsgPort = f.readline().strip()
            msg_server_address = readMsgPort.split(':')[0]
            msg_port = int(readMsgPort.split(':')[1])
            serverName = f.readline().strip()
            serverUUID = f.readline().strip()
            serverAES = f.readline().strip()
    except Exception as e:
        print(f'Error opening file: {e}')
    return msg_server_address, msg_port, serverName, serverUUID, serverAES


def parse_authenticator(payload):
    offset = 0  # Start at the beginning of the buffer
    # Extract client UUID
    enc_key_iv = payload[offset:offset + IV_SIZE]
    offset += IV_SIZE

    # Extract Encrypted Key IV
    server_version = payload[offset:offset + IV_SIZE]
    offset += IV_SIZE

    # Extract Encrypted Nonce (assuming its size is the same as IV for illustration)
    enc_user_UUID = payload[offset:offset + ENC_UUID_SIZE]
    offset += ENC_UUID_SIZE

    # Extract Encrypted AES Key
    enc_server_UUID = payload[offset:offset + ENC_UUID_SIZE]
    offset += ENC_UUID_SIZE

    enc_creation_time = payload[offset:offset + ENC_TIMESTAMP_SIZE]
    offset += ENC_TIMESTAMP_SIZE

    return (enc_key_iv, server_version, enc_user_UUID, enc_server_UUID, enc_creation_time)

def parse_ticket(ticket_raw):
 #   offset = 0

    # Ticket parsing (simplified, assuming fixed size; adjust as needed)
 #   ticket_raw = payload[offset:offset + TICKET_SIZE]
    ticket_offset = 0
    # Assuming ticket includes version, UUIDs, server ID, timestamps, and encrypted info
    # You would need to know the exact structure of your ticket to parse it correctly
    # This is just an illustrative example
    ticket_version, = struct.unpack('<B', ticket_raw[ticket_offset:ticket_offset + SERVER_VERSION_SIZE])
    ticket_offset += SERVER_VERSION_SIZE

    client_UUID = ticket_raw[ticket_offset: ticket_offset + UUID_BYTES]
    ticket_offset += UUID_BYTES

    server_UUID = ticket_raw[ticket_offset: ticket_offset + UUID_BYTES]
    ticket_offset += UUID_BYTES

    creation_time = struct.unpack('<Q', ticket_raw[ticket_offset:ticket_offset + TIMESTAMP_SIZE])[0]
    ticket_offset += TIMESTAMP_SIZE

    ticket_iv = ticket_raw[ticket_offset: ticket_offset + IV_SIZE]
    ticket_offset += IV_SIZE

    enc_server_AES = ticket_raw[ticket_offset: ticket_offset + ENC_AES_SIZE]
    print(f"This is the encrypted server AES: {enc_server_AES}")
    ticket_offset += ENC_AES_SIZE

    enc_expiration_time = ticket_raw[ticket_offset:ticket_offset + ENC_TIMESTAMP_SIZE]
    ticket_offset += ENC_TIMESTAMP_SIZE

    return (ticket_version, client_UUID, server_UUID, creation_time, ticket_iv, enc_server_AES, enc_expiration_time)


def verify_and_respond(auth_client_uuid, auth_server_uuid, auth_creation_time, ticket_client_uuid, ticket_server_uuid, ticket_creation_time, ticket_expiration_time):
    # Convert UUIDs from bytes to hex strings for comparison
    time_now = datetime.now().timestamp()
    auth_client_uuid_hex = auth_client_uuid.hex()
    auth_server_uuid_hex = auth_server_uuid.hex()
    ticket_client_uuid_hex = ticket_client_uuid.hex()
    ticket_server_uuid_hex = ticket_server_uuid.hex()

    # Verify that client UUID and server UUID match
    if auth_client_uuid_hex != ticket_client_uuid_hex or auth_server_uuid_hex != ticket_server_uuid_hex:
        print("Error: UUIDs in the authenticator do not match those in the ticket.")
        return False

    # Verify that the authenticator's creation time is above the ticket's creation time
    if auth_creation_time <= ticket_creation_time:
        print("Error: Authenticator's creation time is not above the ticket's creation time.")
        return False
    if time_now > ticket_expiration_time:
        print("The ticket has already expired, authentication cannot be made.")
        return False
    # If all checks pass, proceed with your logic to acknowledge the AES key send
    # For example, send a success response or the next expected message
    print("Verification successful. Proceeding with the communication.")
    # Implement the success response logic here
    return True

def sendPacket(socket, buffer):
    """ The function pads the buffer with \0 and sends it over the socket. """
    if len(buffer) < PACKET_SIZE:
        buffer += bytearray(PACKET_SIZE - len(buffer))  # Pad with \0

    socket.send(buffer)