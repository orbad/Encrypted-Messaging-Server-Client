// Name: Or Badani
// ID: 316307586

#include "Request.h"

/* Packs the Response struct into a buffer according to the given protocol. */
void Request::packRequest(char* buffer)
{
	memcpy(buffer, _request.URequestHeader.buffer, sizeof(_request.URequestHeader));
	if (_request.payload != nullptr) {
		uint32_t payloadSize = _request.URequestHeader.SRequestHeader.payload_size;
		uint32_t currPayload = payloadSize < PACKET_SIZE - offset() ? payloadSize : PACKET_SIZE - offset();
		memcpy(buffer + sizeof(_request.URequestHeader), _request.payload, currPayload);
	}
}

/* Returns the header offset. */
uint32_t Request::offset() const
{
	return sizeof(_request.URequestHeader);
}

/* ctor */
Request::Request()
{
	memset(_request.URequestHeader.buffer, 0, sizeof(_request.URequestHeader.SRequestHeader));
	_request.URequestHeader.SRequestHeader.version = SERVER_VER;
	_request.payload = nullptr;
}

/* dtor */
Request::~Request()
{
	delete[] _request.payload;
}
