// Name: Or Badani
// ID: 316307586

#include "Client.h"

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
bool Client::getServerInfo(std::string& ip_address, uint16_t& port) const
{
	FileHandler fHandler;
	std::fstream newFile;
	std::string fullLine;
	if (!fHandler.isExistent(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. " << std::endl;
		return false;
	}
	if (!fHandler.openFile(TRANSFER_INFO, newFile, false))
		return false;
	
	if (!std::getline(newFile, fullLine)) {
		std::cerr << "Error reading from transfer file. " << std::endl;
		return false;
	}
	fHandler.closeFile(newFile);

	size_t pos = fullLine.find(":");
	ip_address = fullLine.substr(0, pos);
	fullLine.erase(0, pos + 1);

	int tmp = std::stoi(fullLine);
	if (tmp <= static_cast<int>(UINT16_MAX) && tmp >= 0)
		port = static_cast<uint16_t>(tmp);
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
	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + 1;
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.payload, username.c_str(), username.length() + 1);
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

/* The function handles sending a file over to the server. */
bool Client::sendFile(const SOCKET& sock, sockaddr_in* sa, char* uuid, char* EncryptedAESKey,bool isNewUser) const
{
	unsigned char AESKey[AES_KEY_LEN] = { 0 };
	if (isNewUser){
		if (!sendPubKey(sock, sa, AESKey, uuid))
			return false;
			}
	else {
		if (!decryptAESKey(uuid, EncryptedAESKey, AESKey))
			return false;
		try {
			int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa)); /* Connection to the server */
		}
		catch (std::exception& e) {
			std::cerr << "Exception: " << e.what() << std::endl;
			return false;
		}
	}
	FileHandler fHandler;
	std::fstream requestedFile;
	char requestBuffer[PACKET_SIZE] = { 0 };
	
	if (!fHandler.isExistent(TRANSFER_INFO)) {
		std::cerr << "Error: Transfer file doesn't exist. Cannot retrieve file name. " << std::endl;
		closesocket(sock);
		return false;
	}
	if (!fHandler.openFile(TRANSFER_INFO, requestedFile, false)) {
		std::cerr << "Error: Failed to open TRANSFER INFO file." << std::endl;
		closesocket(sock);
		return false;
	}
	
	std::string filename;

	for (int i = 0; i < TRANSFER_LINES; i++)
		std::getline(requestedFile, filename);
	
	fHandler.closeFile(requestedFile);
	
	if (filename.length() > MAX_CHAR_FILE_LEN) {
		std::cerr << "Error: Filename length too long. " << std::endl;
		closesocket(sock);
		return false;
	}

	if (!fHandler.isExistent(filename)) {
		std::cerr << "Error: Filename doesn't exist. " << std::endl;
		closesocket(sock);
		return false;
	}

	std::cout << "Filename successfully found in transer_info. Preparing to send file." << std::endl;

	Request req;
	uint32_t fileSize = fHandler.getFileSize(filename);
	uint32_t contentSize = fileSize + (AES_BLOCK_SIZE - fileSize % AES_BLOCK_SIZE); // After encryption
	req._request.URequestHeader.SRequestHeader.payload_size = contentSize + MAX_CHAR_FILE_LEN + sizeof(uint32_t);
	uint32_t payloadSize = req._request.URequestHeader.SRequestHeader.payload_size;
	req._request.payload = new char[payloadSize];
	memset(req._request.payload, 0, payloadSize);
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	req._request.URequestHeader.SRequestHeader.code = FILE_SEND;

	uint32_t currPayload = payloadSize < PACKET_SIZE - req.offset() ? payloadSize : PACKET_SIZE - req.offset();

	char* payloadPtr = req._request.payload;
	memcpy(payloadPtr, &contentSize, sizeof(uint32_t));
	payloadPtr += sizeof(uint32_t);
	memcpy(payloadPtr, filename.c_str(), filename.length());
	payloadPtr += MAX_CHAR_FILE_LEN;
	
	// Read File into Payload
	std::string filepath = "./" + filename; // We assume the file is in current dir
	fHandler.openFileBin(filepath, requestedFile, false);
	fHandler.readFileIntoPayload(requestedFile, payloadPtr, fileSize);
	fHandler.closeFile(requestedFile);


	// Calculate checksum of file before encryption
	CRC digest;
	digest.update((unsigned char*)payloadPtr, fileSize);
	uint32_t checksum = digest.digest();

	AESWrapper wrapper(AESKey, AES_KEY_LEN);
	std::string tmpEncryptedData = wrapper.encrypt(payloadPtr, fileSize);
	memcpy(payloadPtr, tmpEncryptedData.c_str(), tmpEncryptedData.length());	
	
	bool crc_confirmed = false;
	size_t tries = 0;

	while (tries < MAX_TRIES && !crc_confirmed) {
		req.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0); // 1028

		uint32_t sizeLeft = payloadSize - currPayload;
		payloadPtr = req._request.payload + currPayload;
		while (sizeLeft > 0) {
			memset(requestBuffer, 0, PACKET_SIZE);
			currPayload = sizeLeft < PACKET_SIZE ? sizeLeft : PACKET_SIZE;
			memcpy(requestBuffer, payloadPtr, currPayload);
			send(sock, requestBuffer, PACKET_SIZE, 0);

			sizeLeft -= currPayload;
			payloadPtr += currPayload;
		} // Finish sending file

		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2103

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code != FILE_OK_CRC) {
			std::cout << "Error: Server responded with an error. " << std::endl;
			closesocket(sock);
			return false;
		}

		std::cout << "Server received file, checking checksum.." << std::endl;

		uint32_t received_checksum;
		memcpy(&received_checksum, res._response.payload + sizeof(uint32_t) + MAX_CHAR_FILE_LEN, sizeof(uint32_t));

		if (checksum == received_checksum) {
			crc_confirmed = true;
			std::cout << "Checksum matches!" << std::endl;
		}
		else {
			tries++;
			std::cout << "Checksum does not match: " << tries << "/3" << " tries." << std::endl;
		}

		Request newReq;
		newReq._request.URequestHeader.SRequestHeader.code = crc_confirmed ? CRC_OK : CRC_INVALID_RETRY;
		if (tries == MAX_TRIES)
			newReq._request.URequestHeader.SRequestHeader.code = CRC_INVALID_EXIT;

		newReq._request.URequestHeader.SRequestHeader.payload_size = MAX_CHAR_FILE_LEN;
		newReq._request.payload = new char[MAX_CHAR_FILE_LEN];
		memcpy(newReq._request.payload, filename.c_str(), filename.length());
		memcpy(newReq._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
		memset(requestBuffer, 0, PACKET_SIZE);
		newReq.packRequest(requestBuffer);
		send(sock, requestBuffer, PACKET_SIZE, 0);
	}

	try {
		char buffer[PACKET_SIZE] = { 0 };
		recv(sock, buffer, PACKET_SIZE, 0); // Expecting Code 2104

		Response res;
		res.unpackResponse(buffer);
		if (res._response.UResponseHeader.SResponseHeader.code == GENERAL_ERROR) {
			std::cout << "Error: Server did not confirm receiving the message. " << std::endl;
			closesocket(sock);
			return false;
		}
		else if(res._response.UResponseHeader.SResponseHeader.code == MSG_RECEIVED){
			std::cout << "The file was successfully (and safely) uploaded to the server." << std::endl;
		}
	}
	catch (std::exception& e) {
		std::cerr << "Couldn't receive final answer. Exception: " << e.what() << std::endl;
		closesocket(sock);
		return false;
	}

	closesocket(sock);
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


