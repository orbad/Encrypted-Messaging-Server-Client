""" Name: Or Badani
    ID: 316307586 """
import struct

from constants import *
import os

def getPorts(filename):
    """
    Gets the port from the file.
    If file doesn't exist, defaults to port 1256.
    """

    auth_port = DEFAULT_PORT
    msg_port = DEFAULT_MSG_PORT
    try:
        with open(filename) as f:
            readAuthPort = f.readline().strip()
            readMsgPort = f.readline().strip()
            auth_server_address = readAuthPort.split(':')[0]
            auth_port = int(readAuthPort.split(':')[1])
            msg_server_address = readMsgPort.split(':')[0]
            msg_port = int(readMsgPort.split(':')[1])

    except Exception as e:
        print(f'Error opening file: {e}')
    return auth_server_address, auth_port, msg_server_address, msg_port

def sendPacket(socket, buffer):
    """ The function pads the buffer with \0 and sends it over the socket. """
    if len(buffer) < PACKET_SIZE:
        buffer += bytearray(PACKET_SIZE - len(buffer))  # Pad with \0

    socket.send(buffer)


def parse_response(buffer):
    version, code, payloadSize = struct.unpack('<BHI', buffer[:RES_HEADER_SIZE])
    print(f"Version: {version}, Code: {code}, Payload Size: {payloadSize}")
    # Ensure that the payload size is within the expected limits
    if payloadSize + RES_HEADER_SIZE > len(buffer) or payloadSize + RES_HEADER_SIZE > PACKET_SIZE:
        raise ValueError("Payload size is larger than the actual data size or exceeds packet size.")

    # Extract the payload
    payload = buffer[7:7 + payloadSize]
    offset = 0  # Start at the beginning of the buffer
    # Extract client UUID
    client_uuid = payload[offset:offset + UUID_BYTES]
    offset += UUID_BYTES

    # Extract Encrypted Key IV
    enc_key_iv = payload[offset:offset + IV_SIZE]
    offset += IV_SIZE

    # Extract Encrypted Nonce (assuming its size is the same as IV for illustration)
    encrypted_nonce = payload[offset:offset + ENC_NONCE_SIZE]
    offset += ENC_NONCE_SIZE

    # Extract Encrypted AES Key
    encrypted_aes_key = payload[offset:offset + ENC_AES_SIZE]
    print(f"Encrypted_AESKey from the server: {encrypted_aes_key}")
    offset += ENC_AES_SIZE

    # Ticket parsing (simplified, assuming fixed size; adjust as needed)
    ticket_raw = payload[offset:offset + TICKET_SIZE]
    # Assuming ticket includes version, UUIDs, server ID, timestamps, and encrypted info
    # You would need to know the exact structure of your ticket to parse it correctly
    # This is just an illustrative example
    ticket_version, = struct.unpack('<B', ticket_raw[:1])
    #creation_time = struct.unpack('<Q', ticket_raw[1 + UUID_BYTES * 2:1 + UUID_BYTES * 2 + TIMESTAMP_SIZE])[0]
    offset += TICKET_SIZE
    # Further parsing of ticket_raw based on your ticket structure...

    # Convert UUIDs from bytes to hex strings for readability (if needed)
    client_uuid_hex = client_uuid.hex()

    # Example: Print extracted data (or process as needed)
    print(f"Client UUID: {client_uuid_hex}")
    print(f"Encrypted Key IV: {enc_key_iv.hex()}")
    print(f"Encrypted Nonce: {encrypted_nonce.hex()}")
    print(f"Encrypted AES Key: {encrypted_aes_key.hex()}")
    return (client_uuid, enc_key_iv, encrypted_nonce, encrypted_aes_key, ticket_raw)

def createDirectory(directory):
    """ If directory doesn't exist, it is created. """
    if not os.path.exists(directory):
        os.mkdir(directory)
