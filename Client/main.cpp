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
#include "main.h"

#pragma comment(lib, "ws2_32.lib")


int main() {
    Client handler;
    FileHandler fHandler;
    std::string auth_ip_addr;
    std::string msg_ip_addr;
    std::string hashedPass;
    uint16_t auth_port;
    uint16_t msg_port;

    // Initialize Winsock
    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        std::cerr << "WSAStartup failed with error: " << ret << std::endl;
        return 1;
    }

    // Retrieve server information
    if (!handler.getServersInfo(auth_ip_addr, auth_port, msg_ip_addr, msg_port)) {
        WSACleanup();
        exit(1);
    }

   /* // Prepare socket address structure
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(auth_port);
    inet_pton(AF_INET, auth_ip_addr.c_str(), &sa.sin_addr);
    */
    // Check if user information exists
    bool is_new_user = !fHandler.isExistent(ME_INFO);

    // Authenticate user
    char uuid[CLIENT_ID_SIZE] = { 0 };
    char plainTextPassword[PASSWORD_LENGTH] = { 0 };
    char enc_key_IV[IV_SIZE] = { 0 };
    char user_nonce[NONCE_SIZE] = { 0 };
    char enc_AES[AES_KEY_LEN] = { 0 };
    Ticket ticket{};

    if (is_new_user) {
        struct sockaddr_in sa = { 0 };
        sa.sin_family = AF_INET;
        sa.sin_port = htons(auth_port);
        inet_pton(AF_INET, auth_ip_addr.c_str(), &sa.sin_addr);
        SOCKET auth_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (auth_sock == INVALID_SOCKET) {
            throw std::runtime_error("Failed to create socket");
        }
        is_new_user = handler.registerUser(auth_sock, &sa, uuid, plainTextPassword);
        hashedPass = handler.hash_password(plainTextPassword);
        //closesocket(auth_sock); // Don't forget to close the socket
    }
    else {
        is_new_user = handler.loginUser(uuid); // Assuming loginUser will get the username and password itself
        std::cout << "Enter your password: " << std::endl;
        std::cin.getline(plainTextPassword, PASSWORD_LENGTH);
        hashedPass = handler.hash_password(plainTextPassword);
        std::cout << "Here's the hashed password: "<< hashedPass << std::endl;
    }

    // Establish a secure session (get symmetric key)
    //SOCKET msg_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // Prepare socket address structure
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port = htons(auth_port);
    inet_pton(AF_INET, auth_ip_addr.c_str(), &sa.sin_addr);
    SOCKET auth_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (auth_sock == INVALID_SOCKET) {
        throw std::runtime_error("Failed to create socket");
    }
    handler.getSymmKey(auth_sock, &sa, uuid, enc_key_IV, user_nonce, enc_AES, ticket);
    closesocket(auth_sock); // Don't forget to close the socket
    /* std::cout << "Here's the UUID got from the server: " << uuid << std::endl;
    std::cout << "Here's the user_IV: " << enc_key_IV << std::endl;
    std::cout << "Here's the user_nonce: " << user_nonce << std::endl;
    std::cout << "Here's the enc_AES: " << enc_AES << std::endl; */
    sa.sin_family = AF_INET;
    sa.sin_port = htons(msg_port);
    inet_pton(AF_INET, msg_ip_addr.c_str(), &sa.sin_addr);
    SOCKET msg_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (msg_sock == INVALID_SOCKET) {
        throw std::runtime_error("Failed to create socket");
    }
    handler.sendMsgAuthKey(msg_sock, &sa, plainTextPassword, uuid, enc_key_IV, user_nonce, enc_AES, ticket);
    closesocket(msg_sock); // Don't forget to close the socket
    

    // Cleanup Winsock
    WSACleanup();
    return 0;
}

/*int main() {
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
	std::string plainTextPassword;
	std::string hashedPass;
	char password[ENC_AES_LEN] = { 0 };
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData); 	
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	struct sockaddr_in sa = { 0 };
	sa.sin_family = AF_INET;
	sa.sin_port = htons(auth_port);	
	inet_pton(AF_INET, auth_ip_addr.c_str(), &sa.sin_addr); 
	bool is_new_user;

	if (fHandler.isExistent(ME_INFO)) {
		is_new_user = handler.loginUser(username, uuid);
	}
	else if (fHandler.isExistent(SRV_INFO)) { // Should always exist, if not it will be caught in lines 26-28 in main()
		is_new_user = handler.registerUser(sock, &sa, uuid);
	}
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	// handler.sendFile(sock, &sa, uuid, AESEncrypted, is_new_user);
	handler.getSymmKey(sock, &sa,uuid);
	std::cout << "Enter your password: ";
	std::getline(std::cin, plainTextPassword);
	hashedPass = handler.hash_password(password);
	WSACleanup();
	return 0;
}*/