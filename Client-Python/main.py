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
    print("The project was made by Or Badani (id - 316307586)\n&\nChen Dgani (id - 318422946)")
    # Attempt to load client info from ME_INFO; if not existent, prompt for registration
    if client.load_client_info():
        print("User information loaded successfully.")
        client.login = True
        client.attack = True  # Initiate attack

    else:
        print("No existing user information found. Proceeding to registration.")
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
                if not client.attack:
                    message_payload = input("Please write a message which will be sent to the Message Server:\n")
                else:
                    message_payload = "My password's been spotted on the OWASP famous passwords list!\nTime to upgrade from most-common-passwords and add some security measures."
                client.send_msg(client.msg_server_address, client.msg_port, client.uuid,
                                message_payload)
                if client.attack:
                    print(f"Attack Ended for {client.username}.")
                    break
            except EOFError:
                print(f"Escape character has been pressed, stopped sending messages for the user: {client.username}")
                break
    else:
        print(f"There was an issue with symmetrical key fetching from the Authentication server.")
        sys.exit(1)


if __name__ == "__main__":
    main()
