import sys
import time

from client import Client
from utils import getPorts
from constants import *


def main():
    # Initialize the client object
    client = Client()
    # Set server address and ports
    client.auth_server_address, client.auth_port, client.msg_server_address, client.msg_port = getPorts(SRV_INFO)

    # Attempt to load client info from ME_INFO; if not existent, prompt for registration
    if client.load_client_info():
        print("User information loaded successfully.")
        client.attack = True  # Initiate attack

    else:
        print("No existing user information found. Proceeding to registration.")
        # Prompt for server details; this could be replaced with a configuration file or constants

        if not client.register_user(client.auth_server_address, client.auth_port):
            print("Failed to register user.")
            sys.exit(1)
        else:
            print("User registered successfully.")

    gotAesKey = client.get_symm_key(client.auth_server_address, client.auth_port, client.uuid, MSG_SRV_UUID)
    if gotAesKey:
        client.send_msg_encryption_key(client.msg_server_address, client.msg_port, client.uuid, MSG_SRV_UUID)
        while True:
            try:
                message_payload = input("Please write a message which will be sent to the Message Server:\n")
                client.send_msg(client.msg_server_address, client.msg_port, client.uuid,
                                message_payload)  # Add do-while loop for messages after the 1st one, maybe do it
                # with EOF character
            except EOFError:
                print(f"Escape character has been pressed, stopped sending messages for the user: {client.username}")
                break
    else:
        print(f"There was an issue with symmetrical key fetching from the Authentication server.")
        sys.exit(1)


if __name__ == "__main__":
    main()
