""" Name: Or Badani
    ID: 316307586 """

import os.path
import sqlite3
import binascii


class Database:
    def __init__(self, name='defensive.db'):
        self.name = name
        self.clients = []
        if not os.path.exists(self.name):
            self.createDatabase()
        else:
            self.loadClientData()

    def databaseExists(self):
        return os.path.exists(self.name)

    def connect(self):
        """ Connects to the database """
        conn = sqlite3.connect(self.name)
        conn.text_factory = bytes
        return conn

    def createDatabase(self):
        """ This method creates the required tables in the DB.
        Ideally this should run one time when the server starts running. """
        if self.databaseExists():
            print("Database already exists.")
            return True
        conn = self.connect()

        try:
            conn.executescript("""
            CREATE TABLE clients (ID CHAR(16) NOT NULL PRIMARY KEY,
            Name CHAR(255) NOT NULL,
            PublicKey CHAR(160),
            LastSeen DATE,
            AESKey CHAR(128)
            );""")

            conn.executescript("""
            CREATE TABLE files (
                ClientID CHAR(16) NOT NULL,               
                FileName CHAR(255),
                PathName CHAR(255),
                Verified INT,
                PRIMARY KEY (ClientID, FileName),
                FOREIGN KEY (ClientID) REFERENCES clients(ID)
            );""")

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            print(f'Database execution failed: {e}')
            return False
    def loadClientData(self):
        """ Load client data from the database. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients")
        self.clients = cur.fetchall()  # Storing client data in self.clients
        print("Database already exists.")
        conn.close()

    def getClients(self):
        """ Returns the list of clients. """
        return self.clients

    def isExistentUser(self, user):
        """ Returns true if a given username exists in the DB. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients WHERE Name = ?", [user])
        info = cur.fetchall()
        conn.close()
        if info:
            return True
        return False

    def isExistentUUID(self, uuid):
        """ Returns true if a given UUID exists in the DB. """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT * FROM clients WHERE ID = ?", [uuid])
        info = cur.fetchall()
        conn.close()
        if info:
            return True
        return False

    def registerClient(self, id, name):
        """ Registers client into the clients table
        Assumes that the client is not there """
        return self.executeCommand(
            "INSERT INTO clients (ID, Name) VALUES (?, ?)", [id, name], True)

    def executeCommand(self, command, args=[], isCommit=False):
        """ Executes a command with the arguments provided """
        conn = self.connect()
        res = False
        try:
            cur = conn.cursor()
            cur.execute(command, args)
            if isCommit:
                conn.commit()
            else:
                res = cur.fetchall()
        except Exception as e:
            print(f'Error: {e}')
        conn.close()
        return res

    def registerFile(self, client_id, filename, pathname, verified):
        """ Registers file into the files table. Assumes that client_id refers to an existing client."""
        return self.executeCommand("INSERT INTO files (ClientID, FileName, PathName, Verified) VALUES (?, ?, ?, ?)",[client_id, filename, pathname, verified], True)

    def setLastSeen(self, id, time):
        """ Given an ID, sets the LastSeen field to the received time. """
        return self.executeCommand("UPDATE clients SET LastSeen = ? WHERE ID = ?", [time, id], True)

    def setAESKey(self, id, key):
        """ Given an ID, sets the AES Key field to the received key. """
        return self.executeCommand("UPDATE clients SET AESKey = ? WHERE ID = ?", [key, id], True)

    def setPubKey(self, id, key):
        """ Given an ID, sets the Public Key field to the received key. """
        return self.executeCommand("UPDATE clients SET PublicKey = ? WHERE ID = ?", [key, id], True)

    def getUserInfo(self, username):
        """
        Retrieves user information from the database based on the username.

        Args:
            username (str): The username of the client.

        Returns:
            dict: A dictionary containing the user's information, or None if the user does not exist.
        """
        byte_username = username.encode('utf-8')
        self.loadClientData()
        # self.clients = self.getClients()
        for client in self.clients:
            if byte_username in client[1]:
                user_info = {"UUID": client[0],
                             "PublicKey": client[2],
                "AESKey": client[4]}
                return user_info
        # if isinstance(username, str):
        #     byte_username = username.encode('utf-8')
        # else:  # If it's already bytes, use it as is
        #     byte_username = username
        # conn = self.connect()
        # cur = conn.cursor()
        # try:
        #     # Prepare the query
        #     cur.execute("SELECT * FROM clients")
        #     result = cur.fetchall()
        # except Exception as e:
        #     print(f'Database execution failed: {e}')
        #     conn.close()
        #     return None  # Return None in case of an error
        #     else:
        #         user_info = None
        # conn.close()  # Close the connection

        # if result:
        #     # If the user exists, create a dictionary to hold the user's information
        #     user_info = {
        #         "UUID": result[0][0],
        #         "AESKey": result[0][4]
        #     }
        #     return user_info
        else:
            # If the user does not exist, return None
            return None