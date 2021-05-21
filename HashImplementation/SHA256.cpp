#include "SHA256.h"
#include "Utility.h"

std::string SHA256::run(const std::string inp)
{
	std::string result;

	for (int i = 0; i < 8; i++)
	{
		final_hash_values_[i] = hash_values_[i];
	}

	std::vector<uint8_t> u8_arr   = preProcess(inp);
	for (int i = 0; i < u8_arr.size(); i += 512)
	{
		handleByChunk(u8_arr, i, std::min((int)u8_arr.size(), i + 512));
	}

	std::stringstream sstream;

	for (int i = 0; i < 8; i++)
	{
		sstream << std::uppercase << std::hex << final_hash_values_[i];
	}

	result = sstream.str();
	// assert(result == "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9");
	//std::cout << result << '\n';

	return result;
}

std::vector<uint8_t> SHA256::preProcess(const std::string inp)
{
	std::vector<uint8_t> result;
	const uint64_t L = inp.size() * 8;

	for (auto c : inp) 
	{
		result.push_back((uint8_t)c);
	}
	result.push_back(0b10000000);

	int num = (((result.size() * 8 + 64)/ 512 + 1) * 512  - result.size() * 8 - 64)/ 8;
	for (int i = 0; i < num; i++) 
	{
		result.push_back(0);
	}

	uint8_t* p = (uint8_t*)&L;
	for (int i = 0; i < 8; i++) 
	{
		result.push_back(p[7 - i]);
	}

	//printU8(result);

	return result;
}

void SHA256::handleByChunk(const std::vector<uint8_t> preProcessArr, int begin, int end)
{
	std::vector<uint32_t> words;
	for (int i = begin; i < end; i += 4)
	{
		uint32_t word = 0;
		
		for (int j = 0; j < 4; j++)
		{
			word |= (preProcessArr[i + j] << (8 * (4 - j - 1)));
		}

		words.push_back(word);
	}

	assert(words.size() == 16);

	const int num = 64 - words.size();
	for (int i = 0; i < num; i++)
	{
		words.push_back(0);
	}

	for (int i = 16; i < 64; i++)
	{
		uint32_t s0 = rotr32(words[i - 15], 7) ^ rotr32(words[i - 15], 18) ^ (words[i - 15] >> 3);
		uint32_t s1 = rotr32(words[i - 2], 17) ^ rotr32(words[i - 2], 19) ^ (words[i - 2] >> 10);
		words[i] = words[i - 16] + s0 + words[i - 7] + s1;
	}

	//printU32(words);

	// assert(words[16] == 0b00110111010001110000001000110111);
	// assert(words[61] == 0b00000001000011111001100101111011);

	// compression

	// S1 = (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
	// ch = (e and f) xor ((not e) and g)
	// temp1 = h + S1 + ch + k[i] + w[i]
	// S0 = (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
	// maj = (a and b) xor (a and c) xor (b and c)
	// temp2 : = S0 + maj
	// h = g
	// g = f
	// f = e
	// e = d + temp1
	// d = c
	// c = b
	// b = a
	// a = temp1 + temp2

	uint32_t a = hash_values_[0];
	uint32_t b = hash_values_[1];
	uint32_t c = hash_values_[2];
	uint32_t d = hash_values_[3];
	uint32_t e = hash_values_[4];
	uint32_t f = hash_values_[5];
	uint32_t g = hash_values_[6];
	uint32_t h = hash_values_[7];

	// assert(a == 0b01101010000010011110011001100111);
	// assert(b == 0b10111011011001111010111010000101);
	// assert(c == 0b00111100011011101111001101110010);
	// assert(d == 0b10100101010011111111010100111010);
	// assert(e == 0b01010001000011100101001001111111);
	// assert(f == 0b10011011000001010110100010001100);
	// assert(g == 0b00011111100000111101100110101011);
	// assert(h == 0b01011011111000001100110100011001);

	for (int i = 0; i < 64; i++)
	{
		uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t temp1 = h + S1 + ch + round_const_[i] + words[i];
		uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temp2 = S0 + maj;

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// assert(a == 0b01001111010000110100000101010010);
	// assert(b == 0b11010111111001011000111110000011);
	// assert(c == 0b01101000101111110101111101100101);
	// assert(d == 0b00110101001011011011011011000000);
	// assert(e == 0b01110011011101101001110101100100);
	// assert(f == 0b11011111010011100001100001100010);
	// assert(g == 0b01110001000001010001111000000001);
	// assert(h == 0b10000111000011110000000011010000);

	final_hash_values_[0] += a;
	final_hash_values_[1] += b;
	final_hash_values_[2] += c;
	final_hash_values_[3] += d;
	final_hash_values_[4] += e;
	final_hash_values_[5] += f;
	final_hash_values_[6] += g;
	final_hash_values_[7] += h;
}

void SHA256::printU8(const std::vector<uint8_t>& arr)
{
	int i = 0;
	for (auto val : arr)
	{
		std::bitset<8> x(val);
		std::cout << x << " ";
		i++;
		if (i == 8) 
		{
			std::cout << std::endl;
			i = 0;
		}
	}
	std::cout << std::endl;
}

void SHA256::printU32(const std::vector<uint32_t>& arr)
{
	int i = 0;
	for (auto val : arr)
	{
		std::bitset<32> x(val);
		std::cout << x << " ";
		i++;
		if (i == 2) 
		{
			std::cout << std::endl;
			i = 0;
		}
	}
	std::cout << std::endl;
}

void SHA256::checkBinary(std::string expected, const std::vector<uint8_t>& arr)
{
	std::string actual;
	for (auto val : arr)
	{
		std::bitset<8> x(val);
		actual += x.to_string();
	}

	assert(expected.compare(actual) == 0);
}