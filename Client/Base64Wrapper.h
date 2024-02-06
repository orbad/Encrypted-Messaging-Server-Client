// Name: Or Badani
// ID: 316307586

#pragma once

#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
