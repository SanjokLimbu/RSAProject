#include "RSA.h"
#include <numeric>

unsigned int KeyGeneration::ConvertASCII(string message) {
	n = 0;
	for (size_t i = 0; i < message.length(); i++) {
		n += (int)message[i];
	}

	return n;
}

unsigned int KeyGeneration::CalculatePhi() {
	phi_n = 1;
	for (size_t i = 2; i < n; i++) {
		if (std::gcd(i, n) == 1)
			phi_n++;
	}

	return phi_n;
}

unsigned int KeyGeneration::CalculateKey() {
	PrivateKey = 0;

	while ((k * phi_n + 1) % e != 0) {
		k++;
		PrivateKey = (k * phi_n + 1) / e;
	}

	return PrivateKey;
}

void KeyGeneration::EncryptMessage(string message) {
	std::vector<int> m;
	cpp_int encoded = 0;
	for (char mes : message) {
		m.push_back((int)mes);
	}
	for (cpp_int hashed : m) {
		encoded = MyPow(hashed, e) % n;
		c.push_back(encoded);
	}
}

void KeyGeneration::DecryptMessage() {
	cpp_int decryptedMessage{};
	std::vector<cpp_int> decoded{};
	string result = "";

	for (cpp_int dehash : c) {
		decryptedMessage = MyPow(dehash, PrivateKey) % n;
		decoded.push_back(decryptedMessage);
	}
	for (cpp_int messages : decoded) {
		result += (char)messages;
	}

	std::cout << result << std::endl;
}

cpp_int KeyGeneration::MyPow(cpp_int x, int p) {
	cpp_int result = x;
	if (p == 0) return 1;
	if (p == 1) return x;

	for (int i = 1; i < p; i++) {
		result *= x;
	}
	std::cout << result << std::endl;
	return result;
}