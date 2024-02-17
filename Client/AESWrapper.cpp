// Name: Or Badani
// ID: 316307586

#include "AESWrapper.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step


unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 16 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
}

const unsigned char* AESWrapper::getKey() const 
{ 
	return _key; 
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}

char* AESWrapper::decrypt(const char* cipher, size_t cipherLength, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
	std::string recovered;

	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
		decryption.SetKeyWithIV(key, key.size(), iv);

		CryptoPP::ArraySource as(reinterpret_cast<const CryptoPP::byte*>(cipher), cipherLength, true,
			new CryptoPP::StreamTransformationFilter(decryption,
				new CryptoPP::StringSink(recovered),
				CryptoPP::StreamTransformationFilter::NO_PADDING // Using NO_PADDING
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Decryption error: " << e.what() << std::endl;
		throw;
	}

	// Manually remove PKCS #7 padding
	if (!recovered.empty()) {
		unsigned char padValue = recovered[recovered.size() - 1];
		if (padValue > 0 && padValue <= CryptoPP::AES::BLOCKSIZE) {
			bool validPadding = true;
			for (size_t i = 0; i < padValue; i++) {
				if (recovered[recovered.size() - i - 1] != padValue) {
					validPadding = false;
					break;
				}
			}
			if (validPadding) {
				recovered.resize(recovered.size() - padValue);
			}
		}
	}

	// Allocate memory for the return value and copy the recovered data into it
	char* result = new char[recovered.size() + 1]; // +1 for null terminator
	std::memcpy(result, recovered.data(), recovered.size());
	result[recovered.size()] = '\0'; // Null-terminate the string
	return result;
}

//This version was working!!
/*std::string AESWrapper::decrypt(const char* cipher, size_t cipherLength, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
	std::string recovered;

	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
		decryption.SetKeyWithIV(key, key.size(), iv);

		// Correctly using ArraySource for binary data decryption
		CryptoPP::ArraySource as(reinterpret_cast<const CryptoPP::byte*>(cipher), cipherLength, true,
			new CryptoPP::StreamTransformationFilter(decryption,
				new CryptoPP::StringSink(recovered),
				CryptoPP::StreamTransformationFilter::NO_PADDING // Specify NO_PADDING here
			)
		);
	}
	catch (const CryptoPP::Exception& e) {
		std::cerr << "Decryption error: " << e.what() << std::endl;
		throw;
	}

	return recovered;
}*/ //This Version was working!!

/*std::string AESWrapper::decrypt(const char* cipher, unsigned int length, const CryptoPP::byte* key, const CryptoPP::byte* iv) {
	if (!key || !iv) {
		throw std::invalid_argument("Key and IV must not be null");
	}

	// Initialize the decryption object using the provided key and IV
	CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
	decryption.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(decryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}*/


/*std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}*/
