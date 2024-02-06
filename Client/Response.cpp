// Name: Or Badani
// ID: 316307586

#include "Response.h"

/* Unpacks the buffer received into the Response struct according to the given protocol. */
void Response::unpackResponse(char* buffer)
{
	memcpy(_response.UResponseHeader.buffer, buffer, sizeof(_response.UResponseHeader));
	char* ptr = buffer + sizeof(_response.UResponseHeader);
	uint32_t payload_size = _response.UResponseHeader.SResponseHeader.payload_size;
	if (payload_size > 0) {
		_response.payload = new char[payload_size];
		memcpy(_response.payload, ptr, payload_size);
	}
}

/* Returns the header offset. */
uint32_t Response::offset() const
{
	return sizeof(_response.UResponseHeader);
}

/* ctor */
Response::Response()
{
	memset(_response.UResponseHeader.buffer, 0, sizeof(_response.UResponseHeader.SResponseHeader));
	_response.UResponseHeader.SResponseHeader.version = SERVER_VER;
	_response.payload = nullptr;
}

/* dtor */
Response::~Response()
{
	delete[] _response.payload;
}
