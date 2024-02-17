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
#include "Ticket.h"
//#include "Ticket.h"



#define PACKET_SIZE 1024
#define USER_LENGTH 255
#define PASSWORD_LENGTH 255
#define ME_INFO "./me.info"
#define TRANSFER_INFO "./transfer.info"
#define SRV_INFO "./srv.info"
#define PRIV_KEY "./priv.key"
#define MSG_SRV_UUID "5dd7496abe3c4ea9bf16e0f2b978aff4"
#define PUB_KEY_LEN 160
#define AES_KEY_LEN 32
#define ENC_AES_SIZE  48
#define ENC_PASSWORD 32
#define AES_BLOCK_SIZE 16
#define NONCE_SIZE 8
#define ENC_NONCE_SIZE 16 
#define IV_SIZE  16
#define CLIENT_ID_SIZE 16
#define CLIENT_ID_LEN 32
#define SERVER_ID_SIZE 16
#define SERVER_ID_LEN 32 // 32 Characters in Hex should be 128 bits which are 16 bytes.
#define TIMESTAMP_SIZE  8
#define ENC_TIMESTAMP_SIZE  16
#define VERSION_SIZE  1
#define MAX_CHAR_FILE_LEN 255
#define TRANSFER_LINES 3
#define PRIV_KEY_LINES 12
// #define ENC_AES_LEN 128
#define MAX_TRIES 3


class Client {
	enum Request_Code { REGISTER_REQUEST = 1024, MSG_ENC_KEY_REQUEST = 1027, LOGIN_REQUEST = 1999, MESSAGE_SEND = 1029}; // Login would need to be dealt down the road
	enum Response_Code { REGISTER_SUCCESS = 1600, REGISTER_ERROR = 1601, MSG_KEY_RECEVIED = 1603, PUB_KEY_ACK = 1604, MSG_RECEIVED = 1605, LOGIN_SUCCESS = 2105, LOGIN_ERROR = 2106, GENERAL_ERROR = 1609 }; // Login would need to be dealt down the road
	bool sendPubKey(const SOCKET&, struct sockaddr_in*, unsigned char*, char*) const;
	bool loadClientInfo(char* uuid) const;  // New method declaration
	bool decryptAESKey(const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const;
	std::string retrievePrivateKey() const;
	unsigned char AESKey[AES_KEY_LEN] = {0};
	char uuid[CLIENT_ID_SIZE] = { 0 };
	uint8_t encKeyIV[IV_SIZE] = { 0 };
	uint8_t encryptedNonce[NONCE_SIZE] = { 0 };
	uint8_t encryptedAESKey[AES_KEY_LEN] = { 0 };
	Ticket myTicket;

public:
	bool getSymmKey(const SOCKET&, struct sockaddr_in*, char* uuid, char* user_IV, char* enc_user_nonce, char* enc_AES, Ticket& ticket) const;
	bool sendMsgAuthKey(const SOCKET&, struct sockaddr_in*, char* plainPassword, char* uuid, char* enc_key_IV, char* enc_user_nonce, char* enc_AES, Ticket& ticket) const;
	bool getServersInfo(std::string&, uint16_t&, std::string&, uint16_t&) const;
	bool registerUser(const SOCKET&, struct sockaddr_in*, char*, char*) const;
	std::string hash_password(const std::string& password);
	// bool sendFile(const SOCKET&, struct sockaddr_in*, char*, char*, bool) const;
	bool loginUser(char*) const;  // New method declaration
};

