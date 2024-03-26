import struct
from constants import *


class Request:
    def __init__(self):
        self.uuid = 0
        self.version = SERVER_VER
        self.code = 0
        self.payloadSize = 0
        self.payload = b''

    def littleEndianUnpack(self, data):
        """ Unpacks binary data received into the correct fields """
        try:
            self.uuid, self.version, self.code, self.payloadSize = struct.unpack(
                f'<{UUID_BYTES}sBHI', data[:REQ_HEADER_SIZE])
            infoToExtract = min(PACKET_SIZE -
                                REQ_HEADER_SIZE, self.payloadSize)
            self.payload = struct.unpack(
                f'<{infoToExtract}s', data[REQ_HEADER_SIZE:REQ_HEADER_SIZE + infoToExtract])[0]

        except Exception as e:
            print(e)


class Response:
    def __init__(self, code, payloadSize):
        self.version = SERVER_VER
        self.code = code
        self.payloadSize = payloadSize
        self.payload = b''

    def littleEndianPack(self):
        """ Packs the data into a struct according to the server's protocol """
        packedData = struct.pack('<BHI', self.version,
                                 self.code, self.payloadSize)
        packedData += self.payload
        return packedData
