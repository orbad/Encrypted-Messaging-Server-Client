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
    offset += ENC_AES_SIZE


    ticket_raw = payload[offset:offset + TICKET_SIZE]
    ticket_version, = struct.unpack('<B', ticket_raw[:1])
    offset += TICKET_SIZE

    return (client_uuid, enc_key_iv, encrypted_nonce, encrypted_aes_key, ticket_raw)
