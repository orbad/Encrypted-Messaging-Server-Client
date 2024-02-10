// Name: Or Badani
// ID: 316307586

#include "Client.h"


std::string SHA256HashString(std::string aString) {
	std::string digest;
	CryptoPP::SHA256 hash;

	CryptoPP::StringSource foo(aString, true,
		new CryptoPP::HashFilter(hash,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(digest))));

	return digest;
}

/* Sends the RSA Public Key and inserts the received AES key into AESKey. */
bool Client::sendPubKey(const SOCKET& sock, sockaddr_in* sa, unsigned char* AESKey, char* uuid) const
{
	RSAPrivateWrapper rsapriv;
	std::string pubkey = rsapriv.getPublicKey();
	RSAPublicWrapper rsapub(pubkey);
	FileHandler fHandler;
	std::fstream newFile;
	std::fstream privFile;


	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	std::string username;
	if (fHandler.isExistent(ME_INFO)) {
		if (!fHandler.openFile(ME_INFO, newFile, false))
			return false;
		std::getline(newFile, username);
		fHandler.closeFile(newFile);
	}
	else if (fHandler.isExistent(TRANSFER_INFO)) {
		if (!fHandler.openFile(TRANSFER_INFO, newFile, false))
			return false;
		std::getline(newFile, username);
		std::getline(newFile, username); // Second line.
		fHandler.closeFile(newFile);
	}
	else {
		std::cerr << "Error: Transfer and info files do not exist. " << std::endl;
		return false;
	}

	std::string privkey = rsapriv.getPrivateKey();
	std::string encoded_privkey = Base64Wrapper::encode(privkey);


	if (!fHandler.openFile(ME_INFO, newFile, true))
		return false;

	fHandler.writeToFile(newFile, "\n", strlen("\n"));
	fHandler.writeToFile(newFile, encoded_privkey.c_str(), encoded_privkey.length());
	fHandler.closeFile(newFile);

	// Open or create the file "priv.key" for writing
	if (!fHandler.openFileOverwrites(PRIV_KEY, privFile))
		return false;

	// Write the private key to "priv.key"
	fHandler.writeToFile(privFile, encoded_privkey.c_str(), encoded_privkey.length());

	// Close the file "priv.key"
	fHandler.closeFile(privFile);

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };
	if (username.length() >= USER_LENGTH) {
		std::cout << "Username doesn't meet the length criteria. " << std::endl;
		return false;
	}

	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + 1 + PUB_KEY_LEN;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	memcpy(req._request.payload, username.c_str(), username.length() + 1);
	memcpy(req._request.payload + username.length() + 1, pubkey.c_str(), PUB_KEY_LEN);
	std::cout << "Sending the following pubkey: \n" << pubkey.c_str() << "." << std::endl;
	req._request.URequestHeader.SRequestHeader.code = PUB_KEY_SEND;

	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);
	if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to receive Public Key. " << std::endl;
		return false;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == PUB_KEY_RECEVIED) {
		RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
		char encryptedAESKey[ENC_AES_LEN] = { 0 };

		memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		std::string decryptedAESKey = rsapriv_other.decrypt(encryptedAESKey, ENC_AES_LEN);
		memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
		std::cout << "The AESKey has been recieved and decrypred successfully." << std::endl;
		return true;
	}
}



/* Places the server info into the received variables. Returns true upon success and false upon failure. */
bool Client::getServersInfo(std::string& auth_ip_address, uint16_t& auth_port, std::string& msg_ip_address, uint16_t& msg_port) const
{
	FileHandler fHandler;
	std::fstream newFile;
	std::string firstLine;
	std::string secondLine;
	if (!fHandler.isExistent(SRV_INFO)) {
		std::cerr << "Error: Servers file doesn't exist. " << std::endl;
		return false;
	}
	if (!fHandler.openFile(SRV_INFO, newFile, false))
		return false;

	if (!std::getline(newFile, firstLine)) {
		std::cerr << "Error reading auth_server details from servers file. " << std::endl;
		return false;
	}
	if (!std::getline(newFile, secondLine)) {
		std::cerr << "Error reading msg_server details from servers file. " << std::endl;
		return false;
	}
	fHandler.closeFile(newFile);

	size_t pos1 = firstLine.find(":");
	auth_ip_address = firstLine.substr(0, pos1);
	firstLine.erase(0, pos1 + 1);
	size_t pos2 = secondLine.find(":");
	msg_ip_address = secondLine.substr(0, pos2);
	secondLine.erase(0, pos2 + 1);

	int tmp1 = std::stoi(firstLine);
	int tmp2 = std::stoi(secondLine);
	if ((tmp1 <= static_cast<int>(UINT16_MAX) && tmp1 >= 0) && (tmp2 <= static_cast<int>(UINT16_MAX) && tmp2 >= 0)) {
	auth_port = static_cast<uint16_t>(tmp1);
	msg_port = static_cast<uint16_t>(tmp2);
    }
	else {
		std::cerr << "Error: Port is invalid." << std::endl;
		return false;
	}
	return true;
}

/* Deals with user registration to the server. */
bool Client::registerUser(const SOCKET& sock, struct sockaddr_in* sa, char* uuid) const
{
	FileHandler fHandler;
	std::fstream newFile;
	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa)); /* Connection to the server */
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	std::string username;
	std::string password;
	std::string uuid_from_ME;
	bool secondLineExists = false; // Flag for checking UUID existence in ME_INFO

	if (fHandler.isExistent(ME_INFO)) { // Checks whether ME_INFO exists in case of login
		if (!fHandler.openFile(ME_INFO, newFile, false))
			return false;
		std::getline(newFile, username);
		if (std::getline(newFile, uuid_from_ME)) { // Attempt to read the UUID line
			secondLineExists = true; // UUID line exists and read successfully
		}
		fHandler.closeFile(newFile);
	}
	else if (!secondLineExists){
		std::cout << "Enter your username: ";
		//std::getline(newFile, username);
		std::cin >> username;
		std::cout << "You entered: " << username << std::endl; //Debugging
		std::cout << "Enter your password: ";
		//std::getline(newFile, username);
		std::cin >> password;
		std::cout << "You entered: " << password << std::endl; //Debugging
		std::cout << "Which is encrypted to: " << password << std::endl; //Debugging
	}
	else {
		std::cerr << "Error: Me.info file does not exist, and name was not for registration." << std::endl;
		return false;
	}
	
	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };
	if (username.length() >= USER_LENGTH) {
		std::cout << "Username doesn't meet the length criteria. " << std::endl;
		return false;
	}
	if (password.length() >= PASSWORD_LENGTH) {
		std::cout << "Password doesn't meet the length criteria. " << std::endl;
		return false;
	}

	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + password.length() + 1;  // +1 for null terminator
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.payload, username.c_str(), username.length());
	req._request.payload[username.length()] = '\0'; // Insert null terminator after the username
	memcpy(req._request.payload + username.length() + 1, password.c_str(), password.length());
	req._request.URequestHeader.SRequestHeader.code = REGISTER_REQUEST;

	req.packRequest(requestBuffer);
	std::cout << "Sending register request for " << username << "." << std::endl;
	send(sock, requestBuffer, PACKET_SIZE, 0);
	
	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);
	if (res._response.UResponseHeader.SResponseHeader.code == REGISTER_ERROR) {
		std::cout << "Error: Failed to register user, the user is already registered, try to login instead. " << std::endl; 
		exit(1);
	}
	else if(res._response.UResponseHeader.SResponseHeader.code == REGISTER_SUCCESS) {
		bool doesMeExist = fHandler.isExistent(ME_INFO);

	
		if (!fHandler.openFile(ME_INFO, newFile, true))
			return false;
		if (doesMeExist) {
			if (!secondLineExists) { // There is only username inside me.info
				fHandler.hexifyToFile(newFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
				fHandler.closeFile(newFile);
			}
			else {
				fHandler.closeFile(newFile);
	
				if (!fHandler.openFileOverwrites(ME_INFO, newFile)) {
					return false;
				}
				fHandler.writeToFile(newFile, username.c_str(), username.length());
				fHandler.writeToFile(newFile, "\n", strlen("\n"));
				fHandler.hexifyToFile(newFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
			}
		}
		else {
			fHandler.writeToFile(newFile, username.c_str(), username.length());
			fHandler.writeToFile(newFile, "\n", strlen("\n"));
			fHandler.hexifyToFile(newFile, res._response.payload, res._response.UResponseHeader.SResponseHeader.payload_size);
			fHandler.closeFile(newFile);
		}
		std::cout << "Updated ME INFO file with name and UUID." << std::endl;
		memcpy(uuid, res._response.payload, CLIENT_ID_SIZE);

		closesocket(sock);
		return true;
	}
	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {

	}
}

bool Client::decryptAESKey(const char* uuid, const char* encryptedAESKey, unsigned char* AESKey) const
{
	FileHandler fHandler;
	RSAPrivateWrapper rsapriv2;
	std::fstream privFile;

	// Open the priv.key file for reading the stored key in there
	if (!fHandler.openFile(PRIV_KEY, privFile, false)) {
		std::cerr << "Error: Failed to open priv.key file." << std::endl;
		return false;
	}

	// Read the encoded private key from priv.key
	std::string encoded_privkey= "";
	std::string temp_privkey_line = "";
	for (int i = 0; i < PRIV_KEY_LINES; i++) {
		std::getline(privFile, temp_privkey_line);
		encoded_privkey += temp_privkey_line;
	}
	fHandler.closeFile(privFile);

	// Assume Base64Wrapper::decode is the method to decode base64 encoded strings
	std::string privkey = Base64Wrapper::decode(encoded_privkey);
	
	// Create RSAPrivateWrapper object with the private key
	RSAPrivateWrapper rsapriv(privkey);
	std::cerr << "Got private key from priv.key." << std::endl;

	// Decrypt the encrypted AES key using the private key
	std::string decryptedAESKey = {0};
	try {
		decryptedAESKey = rsapriv.decrypt(encryptedAESKey, ENC_AES_LEN);
	}
	catch (std::exception& e) {
		std::cerr << "Error - Failed to get the user's private key. Please check if your priv.key matches the user's actual private key. " << std::endl;
		exit(1);
	}
	
	// Copy the decrypted AES key to AESKey buffer
	memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
	std::cerr << "Decrypted the AESKey successfully for the connected user." << std::endl;
	return true;
}



bool Client::loadClientInfo(char* username) const {
	FileHandler fHandler;
	std::fstream newFile;
	std::string usernameStr;


	// Check if 'me.info' exists and open it
	if (fHandler.isExistent(ME_INFO)) {
		std::cout << "Client - login opening me file" << std::endl;

		if (!fHandler.openFile(ME_INFO, newFile, false))
			return false;

		std::getline(newFile, usernameStr);
		memcpy(username, usernameStr.c_str(), USER_LENGTH);
		fHandler.closeFile(newFile);
	}
	else if (fHandler.isExistent(TRANSFER_INFO)) {
		if (!fHandler.openFile(TRANSFER_INFO, newFile, false))
			return false;
		std::getline(newFile, usernameStr);
		std::getline(newFile, usernameStr);
		memcpy(username, usernameStr.c_str(), USER_LENGTH);
		fHandler.closeFile(newFile);
	}

	else {
		std::cerr << "Error: Transfer.info and Me.info files do not exist. " << std::endl;
		return false;  // Return false if 'me.info' does not exist
	}

	return true;  // Return true if username was successfully loaded
}

bool Client::loginUser(const SOCKET& sock, struct sockaddr_in* sa, char* username, char* uuid, char* AESKey) const {
	if (!loadClientInfo(username)) {
		std::cerr << "Error: Failed to load client info." << std::endl;
	}

	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}

	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };

	// Set the request header fields for a login request
	req._request.URequestHeader.SRequestHeader.payload_size = strlen(username)+1;  // +1 for the null terminator
	req._request.payload = new char[strlen(username)+1];  // +1 for the null terminator
	memcpy(req._request.payload, username, strlen(username)+1);  // +1 to include the null terminator
	req._request.URequestHeader.SRequestHeader.code = LOGIN_REQUEST;

	// Pack the request and send it
	req.packRequest(requestBuffer);
	send(sock, requestBuffer, PACKET_SIZE, 0);

	// Receive the server response
	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);

	Response res;
	res.unpackResponse(buffer);

	// Check for a successful login response code
 	if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_SUCCESS) {
		std::cout << "Successfully logged in - " << username << std::endl;
		// Copy the encrypted AES key and the UUID from the response payload
		memcpy(uuid, res._response.payload, CLIENT_ID_SIZE);
		memcpy(AESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		return false; // Return false, since the logged-in user is not new
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == LOGIN_ERROR) {
		std::cout << "Failed to login, this user needs to be registered!" << std::endl;
		closesocket(sock);

		// Create a new socket
		SOCKET new_sock = socket(AF_INET, SOCK_STREAM, 0);
		if (new_sock == INVALID_SOCKET) {
			std::cerr << "Error: Unable to create socket." << std::endl;
			return false;
		}

		// Re-establish the connection
		int connRes = connect(new_sock, (struct sockaddr*)sa, sizeof(*sa));
		if (connRes == SOCKET_ERROR) {
			std::cerr << "Error: Unable to connect to server." << std::endl;
			closesocket(new_sock);  // Don't forget to close the new socket
			return false;
		}

		if (registerUser(new_sock, sa, uuid)) {
			std::cout << "The following user has registered successfully - "<< username << std::endl;
			return true;  // Return true as the user is now registered as a new user
		}
		else {
			std::cout << "Error: Failed to register user." << std::endl;
			return false;
		}
		return false;
	}

	else if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
		std::cout << "Error: Server failed to login or register the user. " << std::endl;
		return false;
	}

	
}


