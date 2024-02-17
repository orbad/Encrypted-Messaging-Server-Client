// Name: Or Badani
// ID: 316307586

#include "Client.h"

std::string Client::hash_password(const std::string& password) {
	using namespace CryptoPP;
	SHA256 hash;
	byte digest[SHA256::DIGESTSIZE]; // Array to store the hash

	// Compute the hash
	hash.CalculateDigest(digest, reinterpret_cast<const byte*>(password.data()), password.size());

	// Manually convert the hash to a hexadecimal string
	std::stringstream hexStream;
	for (int i = 0; i < SHA256::DIGESTSIZE; ++i) {
		hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
	}

	return hexStream.str();
}


std::string generate_secure_nonce() {
	using namespace CryptoPP;

	AutoSeededRandomPool rng; // Secure random number generator

	byte nonce[8]; // Array to hold the 8-byte nonce
	rng.GenerateBlock(nonce, sizeof(nonce)); // Fill the array with random bytes

	// Manually convert the nonce to a hexadecimal string
	std::stringstream hexStream;
	hexStream << std::hex << std::setfill('0');
	for (int i = 0; i < sizeof(nonce); ++i) {
		hexStream << std::setw(2) << static_cast<int>(nonce[i]);
	}

	return hexStream.str();
}

/*std::string msg_server_ip;
if (fHandler.isExistent(SRV_INFO)) {
	if (!fHandler.openFile(SRV_INFO, newFile, false))
		return false;
	std::getline(newFile, msg_server_ip);
	std::getline(newFile, msg_server_ip);
	fHandler.closeFile(newFile);
}
else {
	std::cerr << "Error: Server info file do not exist, can't decalre which server to connect to. " << std::endl;
	return false;
}*/

bool Client::getSymmKey(const SOCKET& sock, sockaddr_in* sa, char* uuid, char* user_IV, char* enc_user_nonce, char* enc_AES, Ticket& ticket) const{
	
	if (connect(sock, (struct sockaddr*)sa, sizeof(*sa)) == SOCKET_ERROR) {
		std::cerr << "Connection failed: " << WSAGetLastError() << std::endl;
		return false;
	}
	std::string msg_srv_uuid = MSG_SRV_UUID;
	std::string nonce = generate_secure_nonce();
	FileHandler fHandler;
	char msg_srv_uuid_bin[SERVER_ID_SIZE] = { 0 };
	char nonce_bin[NONCE_SIZE] = { 0 };
	fHandler.hexStringToBinary(msg_srv_uuid, msg_srv_uuid_bin);
	fHandler.hexStringToBinary(nonce, nonce_bin);
	
	std::cout << "Sending the following UUID: \n" << msg_srv_uuid.c_str() << ".\n" << std::endl;
	std::cout << "Sending the following NONCE: \n" << nonce.c_str() << ".\n" << std::endl;
	std::cout << "From the UUID: \n" << uuid << ".\n" << std::endl;
/*	try {
		int connRes = connect(sock, (struct sockaddr*)sa, sizeof(*sa));
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	if (msg_srv_uuid.length() != SERVER_ID_SIZE || nonce.length() != NONCE_SIZE) {
		std::cerr << "Server UUID or Nonce doesn't meet the length criteria." << std::endl;
		return false;
	}*/


	Request req;
	char requestBuffer[PACKET_SIZE] = { 0 };

	req._request.URequestHeader.SRequestHeader.payload_size = SERVER_ID_SIZE + NONCE_SIZE + 1;  // +1 for null terminator
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.URequestHeader.SRequestHeader.cliend_id, uuid, CLIENT_ID_SIZE);
	memcpy(req._request.payload, msg_srv_uuid_bin, SERVER_ID_SIZE +1);
	req._request.payload[SERVER_ID_SIZE] = '\0'; // Insert null terminator after the username
	memcpy(req._request.payload + SERVER_ID_SIZE +1, nonce_bin, NONCE_SIZE);
	req._request.URequestHeader.SRequestHeader.code = MSG_ENC_KEY_REQUEST;

	req.packRequest(requestBuffer); // Check content
	//std::cout << "Sending key request for the following server:" << msg_server_ip.c_str() << "\n" << std::endl; // send the request here
	send(sock, requestBuffer, PACKET_SIZE, 0);
	/*int sendResult = send(sock, requestBuffer, PACKET_SIZE, 0);
	if (sendResult == SOCKET_ERROR) {
		std::cerr << "Failed to send request: " << WSAGetLastError() << std::endl;
		// Clean up allocated payload memory
		delete[] req._request.payload;
		closesocket(sock);
		WSACleanup();
		return false;
	}*/

	char buffer[PACKET_SIZE] = { 0 };
	recv(sock, buffer, PACKET_SIZE, 0);
	Response res;
	size_t offset = 0;
	res.unpackResponse(buffer);
	if (res._response.UResponseHeader.SResponseHeader.code == MSG_KEY_RECEVIED) {
		memcpy(uuid, res._response.payload + offset, CLIENT_ID_SIZE);
		offset += CLIENT_ID_SIZE;
		memcpy(user_IV, res._response.payload + offset, IV_SIZE);
		offset += IV_SIZE;
		memcpy(enc_user_nonce, res._response.payload + offset, ENC_NONCE_SIZE);
		offset += ENC_NONCE_SIZE;
		memcpy(enc_AES, res._response.payload + offset, ENC_AES_SIZE);
		offset += ENC_AES_SIZE;

		ticket.parseFromBuffer(res._response.payload, offset);

	}
	return true;
}

bool Client::sendMsgAuthKey(const SOCKET&, sockaddr_in*,char* plainPassword, char* uuid, char* enc_key_IV, char* enc_user_nonce, char* enc_AES, Ticket& ticket) const
{
	FileHandler fHandler;
	Client c;
	AESWrapper wrap;

	std::string hashedpassword = c.hash_password(plainPassword);
	char password_bin[ENC_PASSWORD] = { 0 };
	fHandler.hexStringToBinary(hashedpassword, password_bin);

	CryptoPP::SecByteBlock key(reinterpret_cast<const CryptoPP::byte*>(password_bin), ENC_PASSWORD);
	CryptoPP::SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(enc_key_IV), IV_SIZE);
//	unsigned char* enc_nonce_bin = reinterpret_cast<unsigned char*>(enc_user_nonce);
//	unsigned char* enc_aes_bin = reinterpret_cast<unsigned char*>(enc_AES);

	char* decrypted_nonce = wrap.decrypt(enc_user_nonce, ENC_NONCE_SIZE, key, iv);
	char* decrypted_AES = wrap.decrypt(enc_AES, ENC_AES_SIZE, key, iv);
	std::cout << "The decrypted nonce is: " << fHandler.BinaryToHex(decrypted_nonce, NONCE_SIZE) << std::endl;
	std::cout << "The decrypted key is: " << fHandler.BinaryToHex(decrypted_AES, AES_KEY_LEN) << std::endl;





	return true;
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
	//req._request.URequestHeader.SRequestHeader.code = PUB_KEY_SEND;

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
	/*else if (res._response.UResponseHeader.SResponseHeader.code == PUB_KEY_RECEVIED) {
		RSAPrivateWrapper rsapriv_other(rsapriv.getPrivateKey());
		char encryptedAESKey[ENC_AES_LEN] = { 0 };

		memcpy(encryptedAESKey, res._response.payload + CLIENT_ID_SIZE, ENC_AES_LEN);
		std::string decryptedAESKey = rsapriv_other.decrypt(encryptedAESKey, ENC_AES_LEN);
		memcpy(AESKey, decryptedAESKey.c_str(), AES_KEY_LEN);
		std::cout << "The AESKey has been recieved and decrypred successfully." << std::endl;
		return true;
	}*/
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
bool Client::registerUser(const SOCKET& sock, struct sockaddr_in* sa, char* uuid, char* plainTextPassword) const
{
	Client c;
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
		std::getline(std::cin, username);
		std::cout << "You entered: " << username << std::endl; //Debugging
		std::cout << "Enter your password: ";
		//std::getline(newFile, username);
		std::cin.getline(plainTextPassword, PASSWORD_LENGTH);
		std::cout << "You entered: " << plainTextPassword << std::endl; //Debugging
		std::string hashed = c.hash_password(plainTextPassword);
		std::cout << "Which is encrypted to: " << hashed << std::endl; //Debugging
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


	req._request.URequestHeader.SRequestHeader.payload_size = username.length() + sizeof(plainTextPassword)+ 1;  // +1 for null terminator
	req._request.payload = new char[req._request.URequestHeader.SRequestHeader.payload_size];
	memcpy(req._request.payload, username.c_str(), username.length());
	req._request.payload[username.length()] = '\0'; // Insert null terminator after the username
	memcpy(req._request.payload + username.length() + 1, plainTextPassword, sizeof(plainTextPassword));
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



bool Client::loadClientInfo(char* uuid) const {
	FileHandler fHandler;
	std::fstream newFile;
	std::string usernameStr;
	std::string clientUUID;


	// Check if 'me.info' exists and open it
	if (fHandler.isExistent(ME_INFO)) {
		std::cout << "Client - login opening me file" << std::endl;

		if (!fHandler.openFile(ME_INFO, newFile, false))
			return false;

		std::getline(newFile, usernameStr);
		memcpy(uuid, usernameStr.c_str(), usernameStr.length());
		std::cout << "Client - login, username: " << usernameStr << std::endl;
		std::getline(newFile, clientUUID);
		// here the function should be inserted, uuid in the line beneath should be 16 bytes
		fHandler.hexStringToBinary(clientUUID, uuid);
		std::cout << "Client - login, username: " << clientUUID << std::endl;
		fHandler.closeFile(newFile);
	}

	else {
		std::cerr << "Error: Me.info files do not exist. " << std::endl;
		return false;  // Return false if 'me.info' does not exist
	}

	return true;  // Return true if username was successfully loaded
}

bool Client::loginUser(char* uuid) const {
	if (!loadClientInfo(uuid)) {
		std::cerr << "Error: Failed to load client info." << std::endl;
	}
		return false; // Return false, since the logged-in user is not new
	}


