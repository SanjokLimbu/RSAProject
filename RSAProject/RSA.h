#ifndef RSA_H
#define RSA_H

#include <iostream>
#include <string>
#include <vector>
#include <boost\multiprecision\cpp_int.hpp>

using std::string;
using namespace boost::multiprecision;

class KeyGeneration {
private:
	unsigned int n{};
	unsigned int k = 2;
	unsigned int e = 7;
	unsigned int phi_n{};
	unsigned int PrivateKey{};
	std::vector<cpp_int> c;

public:
	unsigned int ConvertASCII(string message);
	unsigned int CalculatePhi();
	unsigned int CalculateKey();
	void EncryptMessage(string message);
	void DecryptMessage();
	cpp_int MyPow(cpp_int x, int p);
};

#endif // !RSA_H
