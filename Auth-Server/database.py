""" Name: Or Badani
    ID: 316307586 """

import os.path
import sqlite3
import binascii


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

    def getUserInfo(self, username, hashed_password):
        """Retrieves user information based on the username."""
        for client in self.clients:
            if client[1] == username and client[2] == hashed_password:
                return {
                    "UUID": client[0],
                    "Name": client[1],
                    "PasswordHash": client[2],
                    "LastSeen": client[3]
                }
        return None

    def updateLastSeen(self, uuid, lastSeen):
        """Updates the last seen date for a given user ID."""
        for client in self.clients:
            if client[0] == uuid:
                client[3] = lastSeen
                break
        self.saveClientData()