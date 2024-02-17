// Name: Or Badani
// ID: 316307586

/*
Request.h
*/

#pragma once
#include <iostream>
#include <stdint.h>


#define CLIENT_SIZE 16
#define SERVER_VER 24
#define PACKET_SIZE 1024

class Request {
	friend class Client;
#pragma pack(push, 1)
	struct RequestFormat {
		union URequestHeader {
			struct SRequestHeader {
				char cliend_id[CLIENT_SIZE];
				uint8_t version;
				uint16_t code;
				uint32_t payload_size;
			} SRequestHeader;
			char buffer[sizeof(SRequestHeader)];
		} URequestHeader;
		char* payload;
	} _request;
#pragma pack(pop)
	void packRequest(char*);
	uint32_t offset() const;
	Request();
	~Request();
};