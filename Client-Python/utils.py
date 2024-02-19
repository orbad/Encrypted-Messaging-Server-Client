""" Name: Or Badani
    ID: 316307586 """

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
            auth_port = int(readAuthPort)
            msg_port = int(readMsgPort)

    except Exception as e:
        print(f'Error opening file: {e}')
    return auth_port, msg_port

def sendPacket(socket, buffer):
    """ The function pads the buffer with \0 and sends it over the socket. """
    if len(buffer) < PACKET_SIZE:
        buffer += bytearray(PACKET_SIZE - len(buffer))  # Pad with \0

    socket.send(buffer)


def createDirectory(directory):
    """ If directory doesn't exist, it is created. """
    if not os.path.exists(directory):
        os.mkdir(directory)
