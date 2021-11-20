#include "RSA.h"
#include "EllipticCurve.h"

int main() {

	//This is for RSA

	string message{};
	std::cout << "Enter message" << std::endl;
	std::getline(std::cin, message);

	//Generate private key
	KeyGeneration key;
	key.ConvertASCII(message);
	key.CalculatePhi();
	key.CalculateKey();

	//Message to encrypt, decrypt, digital signature and verify
	std::cout << "Enter message" << std::endl;
	std::getline(std::cin, message);
	key.EncryptMessage(message);
	key.DecryptMessage();
	key.RSAHash(message);

	//This is for ECC

	//Pass Generator point
	int GenNumbersA, GenNumbersB;

	std::cout << "First Generator point" << std::endl;
	std::cin >> GenNumbersA;
	std::cout << "Second Generator point" << std::endl;
	std::cin >> GenNumbersB;

	EllipticCurve ECC;
	ECC.Generator(GenNumbersA, GenNumbersB);
	ECC.GeneratePublicKey();
	return 0;
}