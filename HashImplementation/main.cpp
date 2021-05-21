#include <iostream>
#include "SHA256.h"

int main() 
{
	std::string inp = "hello world";

	SHA256 sha_256_instance = SHA256::getInstance();

	std::cout << "SHA 256: " << sha_256_instance.run(inp) << std::endl;
}