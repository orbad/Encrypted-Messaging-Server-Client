""" Name: Or Badani
    ID: 316307586 """

import server
import utils

# Main function - runs the server.
if __name__ == '__main__':
    msgServer = server.Server()
    msgServer.address, msgServer.port, msgServer.host, msgServer.srvUUID, msgServer.AESKey = utils.getPort('msg.info')
    msgServer.run()
