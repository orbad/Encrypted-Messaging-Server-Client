// Name: Or Badani
// ID: 316307586

#include "FileHandler.h"

/* Opens the file as binary, and returns true upon success. If the directories don't exist, they will be created. */
bool FileHandler::openFile(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flag = writeFlag ?  (std::fstream::out | std::fstream::app) : std::fstream::in;
		thisFile.open(fileDestination.c_str(), flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

/* Opens the file as binary, and returns true upon success. If the directories don't exist, they will be created. */
bool FileHandler::openFileBin(const std::string& fileDestination, std::fstream& thisFile, bool writeFlag)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flags = writeFlag ? (std::fstream::binary | std::fstream::out) : (std::fstream::binary | std::fstream::in);
		thisFile.open(fileDestination.c_str(), flags);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

/* Opens the file as binary, and returns true upon success, overwrites written content. If the directories don't exist, they will be created. */
bool FileHandler::openFileOverwrites(const std::string& fileDestination, std::fstream& thisFile)
{
	std::filesystem::path pathToCheck = fileDestination;
	try {
		std::filesystem::create_directories(pathToCheck.parent_path());
		auto flag = std::fstream::binary | std::fstream::out | std::fstream::trunc;
		thisFile.open(fileDestination.c_str(), flag);
		return thisFile.is_open();
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

/* Closes a file, and returns true upon success. */
bool FileHandler::closeFile(std::fstream& thisFile)
{
	try {
		thisFile.close();
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

/* Writes content into a file. fstream object is received, so the calling function is responsible for opening. */
bool FileHandler::writeToFile(std::fstream& thisFile, const char* content, uint32_t size)
{
	try {
		thisFile.write(content, size);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
}

/* Reads the contents of a file into the payload buffer */
bool FileHandler::readFileIntoPayload(std::fstream& thisFile, char* payload, uint32_t count)
{
	try {
		thisFile.read(payload, count);
		return true;
	}
	catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
		return false;
	}
	return false;
}

/* Given a buffer, writes the buffer in hex into a file. (Inspired by the code provided by the lecturers, with small tweaks)*/
void FileHandler::hexifyToFile(std::fstream& thisFile, const char* buffer, unsigned int length)
{
	std::ios::fmtflags f(thisFile.flags());
	thisFile << std::hex;
	for (size_t i = 0; i < length; i++)
		thisFile << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
	thisFile.flags(f);
}

/* Returns true if fileDestination exists on the server, otherwise returns false. */
bool FileHandler::isExistent(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::exists(fileDestination);
}

/* Returns the size of file received. This function assumes that 4 bytes are enough to store the size. */
uint32_t FileHandler::getFileSize(const std::string& fileDestination)
{
	std::filesystem::path pathToCheck = fileDestination;
	return std::filesystem::file_size(pathToCheck);
}