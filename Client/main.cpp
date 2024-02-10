// Name: Or Badani
// ID: 316307586

#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <string>
#include <iomanip>

#include <WS2tcpip.h>
#include <WinSock2.h>
#include <Windows.h>
#include "Client.h"

#include <chrono>
#include <thread>

#pragma comment(lib, "ws2_32.lib")


int main() {
	Client handler;
	FileHandler fHandler;
	std::string auth_ip_addr;
	std::string msg_ip_addr;
	uint16_t auth_port;
	uint16_t msg_port;
	if (!handler.getServersInfo(auth_ip_addr, auth_port, msg_ip_addr, msg_port))
		exit(1);
	char uuid[CLIENT_ID_SIZE] = { 0 };
	char username[USER_LENGTH] = { 0 };
	char AESEncrypted[ENC_AES_LEN] = { 0 };
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData); 	
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons(auth_port);	
	inet_pton(AF_INET, auth_ip_addr.c_str(), &sa.sin_addr); 
	bool is_new_user;

	if (fHandler.isExistent(ME_INFO)) {
		is_new_user = handler.loginUser(sock, &sa, username, uuid, AESEncrypted);
	}
	else if (fHandler.isExistent(SRV_INFO)) { // Should always exist, if not it will be caught in lines 26-28 in main()
		is_new_user = handler.registerUser(sock, &sa, uuid);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	// handler.sendFile(sock, &sa, uuid, AESEncrypted, is_new_user);
	
	WSACleanup();
	return 0;
}