import sys
from client import Client
from utils import getPorts
from constants import *


def main():
    # Initialize the client object
    client = Client()

    # Set server address and ports
    client.server_address, _ = '127.0.0.1', '127.0.0.1'  # Assuming both addresses are the same in this context
    client.auth_port, client.msg_port = getPorts(SRV_INFO)

    # Attempt to load client info from ME_INFO; if not existent, prompt for registration
    if client.load_client_info():
        print("User information loaded successfully.")
    else:
        print("No existing user information found. Proceeding to registration.")
        # Prompt for server details; this could be replaced with a configuration file or constants
        client.server_address = input("Enter the server address (default: localhost): ") or 'localhost'
        client.auth_port = int(input(f"Enter the auth port (default: {DEFAULT_PORT}): ") or DEFAULT_PORT)

        if not client.register_user(client.server_address, client.auth_port):
            print("Failed to register user.")
            sys.exit(1)
        else:
            print("User registered successfully.")

    # Assuming additional functionality follows registration/login
    # This could include establishing a message session, fetching data from the server, etc.

    # Close the client connection
    client.close()


if __name__ == "__main__":
    main()
