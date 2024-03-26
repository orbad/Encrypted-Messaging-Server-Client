import os.path
from constants import *


class Database:
    def __init__(self, file_name='clients.info'):
        self.file_name = file_name
        self.clients = []
        self.loadClientData()

    def loadClientData(self):
        """Load client data from the file."""
        if os.path.exists(self.file_name):
            with open(self.file_name, 'r') as file:
                self.clients = [line.strip().split(':') for line in file.readlines()]

    def saveClientData(self):
        try:
            with open(self.file_name, 'w') as file:
                for client in self.clients:
                    line = ':'.join(map(str, client)) + '\n'
                    file.write(line)
        except Exception as e:
            print(f"Failed to save client data: {e}")

    def loadMessageServerKey(self):
        try:
            with open(MSG_INFO, 'r') as file:
                content = file.readlines()
                return content[3]
        except Exception as e:
            print(f"Failed to save client data: {e}")

    def registerClient(self, id, name, passwordHash, lastSeen):
        """Registers a new client or updates an existing one based on ID."""
        for client in self.clients:
            if client[0] == id:  # Client exists, update their info
                client[1] = name
                client[2] = passwordHash
                client[3] = lastSeen
                break
        else:  # New client
            self.clients.append([id, name, passwordHash, lastSeen])
        self.saveClientData()

    def isExistentUser(self, name):
        """Checks if a user with the given name exists."""
        return any(client[1] == name for client in self.clients)

    def isExistentUUID(self, uuid):
        """Checks if a user with the given ID exists."""
        return any(client[0] == uuid for client in self.clients)

    def getUserPassword(self, uuid):
        """Retrieves user secret key based on the UUID."""
        found = False
        for client in self.clients:
            if client[0] == uuid:
                found = True
                return client[2]
        if not found:
            print(f"Failed login attempt with uuid: {uuid}, the username or password is incorrect.")
        return None

    def updateLastSeen(self, uuid, lastSeen):
        """Updates the last seen date for a given user ID."""
        for client in self.clients:
            if client[0] == uuid:
                client[3] = lastSeen
                break
        self.saveClientData()