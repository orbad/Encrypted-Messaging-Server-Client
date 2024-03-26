import server
import utils

# Main function - runs the server.
if __name__ == '__main__':
    port = utils.getPort('port.info')
    myServer = server.Server('', port)
    myServer.run()
