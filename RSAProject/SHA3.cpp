#include "SHA3.h"

#define S_INDEX(x, y, z) (W * (5 * y + x) + z)
#define Y_0(x, z) (W * (5 * 0 + x) + z)
#define Y_1(x, z) (W * (5 * 1 + x) + z)
#define Y_2(x, z) (W * (5 * 2 + x) + z)
#define Y_3(x, z) (W * (5 * 3 + x) + z)
#define Y_4(x, z) (W * (5 * 4 + x) + z)
#define C_INDEX(x, z) (W * (5 * 0 + (x + 4) % 5) + z)
#define C_ROT_INDEX(x, z) (W * (5 * 0 + (x + 1) % 5) + (z - 1) % W)
#define PIE_SCRAMBLE(x, y, z) (W * (5 * ((2 * x + 3 * y) % 5) + y) + z)

void SHA3::Preprocessing(string message) {
	string input = message;
	size_t len = input.length();
	size_t originallen = len;
	do {
		input += '\0';
		len++;
	} while (len % 136 != 0);

	//calculate blocks required
	size_t blocksreq = len / 136;
	size_t count{}, in{}, bitcount{};

	while (count != blocksreq) {
		bitcount = 0;
		for (size_t i = 0; i < 136; i++){
			std::bitset<8> mes = input[in++];
			for (size_t j = 0; j < 8; j++) {
				chunks[bitcount] = mes[j];
				bitcount++;
			}
		}
		count++;
		if (count != blocksreq) {
			Absorb(chunks);
		}
		else {
			chunks.flip(originallen * 8 + 1);
			chunks.flip(originallen * 8 + 2);
			chunks.flip(1087);
			Absorb(chunks);
			Squeeze();
		}
	}
}

void SHA3::Absorb(std::bitset<1088> message) {
	uint8_t fcounter{}, rotcounter{}, W{ 64 }; size_t counter{}; 
	for (size_t i = 0; i < message.size(); i++) {
		state[i] = state[i] ^ message[i];
	}
	std::bitset<320> C{}, D{};
	std::bitset<1> chitemp{ 1 };
	while (fcounter < 24) {
		//theta step A[x, y, z] = S [w(5y + x) + z].
		for (size_t x = 0; x < 5; x++) {
			for (size_t z = 0; z < W; z++) {
				C[Y_0(x, z)] = state[Y_0(x, z)] ^ state[Y_1(x, z)] ^ state[Y_2(x, z)] ^ state[Y_3(x, z)] ^ state[Y_4(x, z)];
			}
		}
		for (size_t x = 0; x < 5; x++) {
			for (size_t z = 0; z < W; z++) {
				D[Y_0(x, z)] = C[C_INDEX(x, z)] ^ C[(C_ROT_INDEX(x, z))];
			}
		}
		for (size_t y = 0; y < 5; y++) {
			for (size_t x = 0; x < 5; x++) {
				for (size_t z = 0; z < W; z++) {
					state[S_INDEX(x, y, z)] = state[S_INDEX(x, y, z)] ^ D[Y_0(x, z)];
					counter++;
				}
			}
		}
		//Rho step
		rotcounter = 0;
		for (size_t y = 0; y < 5; y++) {
			for (size_t x = 0; x < 5; x++) {
				uint8_t rotconst = RotationConstants[rotcounter++];
				if (rotconst == 0) {
					//Pie Step
					for (size_t z = 0; z < W; z++) {
						invertedstate[S_INDEX(x, y, z)] = state[S_INDEX(x, y, z)];
					}
				}
				else {
					for (size_t z = 0; z < W; z++) {
						rotstate[(z + rotconst) % W] = state[S_INDEX(x, y, z)];
					}
					//Pie step
					for (size_t z = 0; z < W; z++) {
						invertedstate[PIE_SCRAMBLE(x, y, z)] = rotstate[z];
					}
				}
			}
		}
		//Chi step
		for (size_t y = 0; y < 5; y++) {
			for (size_t x = 0; x < 5; x++) {
				for (size_t z = 0; z < W; z++) {
					state[S_INDEX(x, y, z)] = invertedstate[S_INDEX(x, y, z)] ^ ((invertedstate[W * (5 * y + (x + 1) % 5) + z] ^ chitemp[0]) & invertedstate[W * (5 * y + (x + 2) % 5) + z]);
				}
			}
		}
		//Iota step
		std::bitset<64> RCon{};
		RCon = RoundConstant[fcounter];
		for (size_t z = 0; z < W; z++) {
			state[W * (5 * 0 + 0) + z] = state[W * (5 * 0 + 0) + z] ^ RCon[z];
		}
		fcounter++;
	}
	//Squeeze();
}

void SHA3::Squeeze() {
	std::bitset<256> hash{};
	std::bitset<8> text[32];
	size_t count{};
	for (size_t i = 0; i < hash.size(); i++) {
		hash[i] = state[i];
	}
	for (size_t i = 0; i < 32; i++) {
		for (size_t j = 0; j < 8; j++) {
			text[i][j] = hash[count++];
		}
		unsigned long mes = text[i].to_ulong();
		std::cout << std::setfill('0') << std::setw(2) << std::hex << mes;
	}
}