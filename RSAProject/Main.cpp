#include "RSA.h"

int main() {
	string message{};
	std::cout << "Enter message" << std::endl;
	std::getline(std::cin, message);

	KeyGeneration key;
	key.ConvertASCII(message);
	key.CalculatePhi();
	key.CalculateKey();
	std::cout << "Enter message" << std::endl;
	std::getline(std::cin, message);
	key.EncryptMessage(message);
	key.DecryptMessage();

	return 0;
}