// Name: Or Badani
// ID: 316307586

#pragma once

#include <string>
#include <cryptlib.h>
#include <rijndael.h>
#include <modes.h>
#include <osrng.h>
#include <secblock.h>
#include <string>

class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);
public:
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	AESWrapper();
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	char* decrypt(const char* cipher, size_t cipher_size,const CryptoPP::SecByteBlock& decryptKey, const CryptoPP::SecByteBlock& decryptIv);
//	std::string decrypt(const char* cipher, unsigned int length, const CryptoPP::byte* key, const CryptoPP::byte* iv);
	//std::string decrypt(const char* cipher, unsigned int length);
};


