""" Name: Or Badani
    ID: 316307586 """

import server
import utils

# Main function - runs the server.
if __name__ == '__main__':
    port = utils.getPort('port.info')
    msgPort = utils.getMessagePort('msg.info')
    myServer = server.Server('', port, msgPort)
    myServer.run()
