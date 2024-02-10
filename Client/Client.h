// Name: Or Badani
// ID: 316307586

/*
Client.h
*/

#pragma once
#include <WinSock2.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <string>
#include "FileHandler.h"
#include "Response.h"
#include "Request.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "CRC.h"


#define PACKET_SIZE 1024
#define USER_LENGTH 255
#define PASSWORD_LENGTH 32
#define ME_INFO "./me.info"
#define TRANSFER_INFO "./transfer.info"
#define PRIV_KEY "./priv.key"
#define PUB_KEY_LEN 160
#define AES_KEY_LEN 16
#define AES_BLOCK_SIZE 16
#define CLIENT_ID_SIZE 16
#define MAX_CHAR_FILE_LEN 255
#define TRANSFER_LINES 3
#define PRIV_KEY_LINES 12
#define ENC_AES_LEN 128
#define MAX_TRIES 3


class Client {
	enum Request_Code { REGISTER_REQUEST = 1024, PUB_KEY_SEND = 1028, LOGIN_REQUEST = 1027, MESSAGE_SEND = 1029}; // Login would need to be dealt down the road
	enum Response_Code { REGISTER_SUCCESS = 1600, REGISTER_ERROR = 1601,PUB_KEY_RECEVIED = 1603, PUB_KEY_ACK = 1604, MSG_RECEIVED = 1605, LOGIN_SUCCESS = 2105, LOGIN_ERROR = 2106, GENERAL_ERROR = 1609 }; // Login would need to be dealt down the road
	bool sendPubKey(const SOCKET&, struct sockaddr_in*, unsigned char*, char*) const;
	bool loadClientInfo(char* uuid) const;  // New method declaration
	bool decryptAESKey(const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const;
	std::string retrievePrivateKey() const;
	unsigned char AESKey[AES_KEY_LEN] = {0};
	char uuid[CLIENT_ID_SIZE] = { 0 };

public:
	bool getServerInfo(std::string&, uint16_t&) const;
	bool registerUser(const SOCKET&, struct sockaddr_in*, char*) const;
	bool sendFile(const SOCKET&, struct sockaddr_in*, char*, char*, bool) const;
	bool loginUser(const SOCKET & sock, struct sockaddr_in* sa, char*, char*, char*) const;  // New method declaration
};