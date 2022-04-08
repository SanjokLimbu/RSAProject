#ifndef SHA3_H
#define SHA3_H

#include <vector>
#include <string>
#include <bitset>
#include <iostream>
#include <iomanip>

using std::string;

//SHA3 - 256
class SHA3 {

private:
	std::bitset<1088> chunks{};
	std::bitset<1600> state{}, invertedstate{}; std::bitset<64> rotstate{};
	const uint8_t RotationConstants[25]{
		0, 1, 62, 28, 27,
		36, 44, 6, 55, 20,
		3, 10, 43, 25, 39,
		41, 45, 15, 21, 8,
		18, 2, 61, 56, 14
	};
	const uint64_t RoundConstant[24] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008,
	};

public:
	void Preprocessing(string message);
	void Absorb(std::bitset<1088> message);
	void Squeeze();
};
#endif // !SHA3_H
