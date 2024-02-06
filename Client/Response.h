// Name: Or Badani
// ID: 316307586

/*
Response.h
*/

#pragma once
#include <iostream>
#include <stdint.h>


#define SERVER_VER 3
#define PACKET_SIZE 1024 // see how to do this better 1 time

class Response {
	friend class Client;
#pragma pack(push, 1)
	struct ResponseFormat {
		union UResponseHeader {
			struct SResponseHeader {
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} SResponseHeader;
			char buffer[sizeof(SResponseHeader)];
		} UResponseHeader;
		char* payload;
	} _response;
#pragma pack(pop)
	void unpackResponse(char*);
	uint32_t offset() const;
	Response();
	~Response();
};